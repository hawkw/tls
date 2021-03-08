use super::*;
use crate::common::IoSession;
use rustls::Session;

/// A wrapper around an underlying raw stream which implements the TLS or SSL
/// protocol.
#[derive(Debug)]
pub struct TlsStream<IO> {
    pub(crate) io: IO,
    pub(crate) session: ClientSession,
    pub(crate) state: TlsState,
}

impl<IO> TlsStream<IO> {
    #[inline]
    pub fn get_ref(&self) -> (&IO, &ClientSession) {
        (&self.io, &self.session)
    }

    #[inline]
    pub fn get_mut(&mut self) -> (&mut IO, &mut ClientSession) {
        (&mut self.io, &mut self.session)
    }

    #[inline]
    pub fn into_inner(self) -> (IO, ClientSession) {
        (self.io, self.session)
    }
}

impl<IO> IoSession for TlsStream<IO> {
    type Io = IO;
    type Session = ClientSession;

    #[inline]
    fn skip_handshake(&self) -> bool {
        self.state.is_early_data()
    }

    #[inline]
    fn get_mut(&mut self) -> (&mut TlsState, &mut Self::Io, &mut Self::Session) {
        (&mut self.state, &mut self.io, &mut self.session)
    }

    #[inline]
    fn into_io(self) -> Self::Io {
        self.io
    }
}

impl<IO> AsyncRead for TlsStream<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let _span = trace_span!("TlsStream::poll_read", role = %"client", state = ?self.state);
        match self.state {
            #[cfg(feature = "early-data")]
            TlsState::EarlyData(..) => Poll::Pending,
            TlsState::Stream | TlsState::WriteShutdown => {
                let this = self.get_mut();
                let mut stream =
                    Stream::new(&mut this.io, &mut this.session).set_eof(!this.state.readable());
                let prev = buf.remaining();
                let read = stream.as_mut_pin().poll_read(cx, buf);
                trace!(?read, prev);
                match read {
                    Poll::Ready(Ok(())) => {
                        if prev == buf.remaining() {
                            trace!(reason = %"eof", "shutdown read");
                            this.state.shutdown_read();
                        }

                        Poll::Ready(Ok(()))
                    }
                    Poll::Ready(Err(ref e)) if e.kind() == io::ErrorKind::ConnectionAborted => {
                        trace!(reason = %"aborted", "shutdown read");
                        this.state.shutdown_read();
                        Poll::Ready(Ok(()))
                    }
                    output => output,
                }
            }
            TlsState::ReadShutdown | TlsState::FullyShutdown => {
                trace!(read = %"already shut down");
                Poll::Ready(Ok(()))
            }
        }
    }
}

impl<IO> AsyncWrite for TlsStream<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    /// Note: that it does not guarantee the final data to be sent.
    /// To be cautious, you must manually call `flush`.
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let _span = trace_span!("TlsStream::poll_write", role = %"client", state = ?self.state);
        let this = self.get_mut();
        let mut stream =
            Stream::new(&mut this.io, &mut this.session).set_eof(!this.state.readable());

        #[allow(clippy::match_single_binding)]
        let write = match this.state {
            #[cfg(feature = "early-data")]
            TlsState::EarlyData(ref mut pos, ref mut data) => {
                use std::io::Write;

                // write early data
                if let Some(mut early_data) = stream.session.early_data() {
                    let write = early_data.write(buf);
                    trace!(?write, "write early data");
                    let len = match write {
                        Ok(n) => n,
                        Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {
                            return Poll::Pending
                        }
                        Err(err) => return Poll::Ready(Err(err)),
                    };
                    if len != 0 {
                        data.extend_from_slice(&buf[..len]);
                        return Poll::Ready(Ok(len));
                    }
                }

                // complete handshake
                while stream.session.is_handshaking() {
                    let complete = stream.handshake(cx);
                    trace!(?complete, "handshaking");
                    ready!(complete)?;
                }

                // write early data (fallback)
                if !stream.session.is_early_data_accepted() {
                    trace!("fallback write early data");
                    while *pos < data.len() {
                        let len = ready!(stream.as_mut_pin().poll_write(cx, &data[*pos..]))?;
                        *pos += len;
                    }
                }

                // end
                this.state = TlsState::Stream;
                stream.as_mut_pin().poll_write(cx, buf)
            }
            _ => stream.as_mut_pin().poll_write(cx, buf),
        };
        trace!(?write);
        write
    }

    /// Note: that it does not guarantee the final data to be sent.
    /// To be cautious, you must manually call `flush`.
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let _span =
            trace_span!("TlsStream::poll_write_vectored", role = %"client", state = ?self.state);
        let this = self.get_mut();
        let mut stream =
            Stream::new(&mut this.io, &mut this.session).set_eof(!this.state.readable());

        #[allow(clippy::match_single_binding)]
        let write = match this.state {
            #[cfg(feature = "early-data")]
            TlsState::EarlyData(ref mut pos, ref mut data) => {
                use std::io::Write;

                // write early data
                if let Some(mut early_data) = stream.session.early_data() {
                    let len = match early_data.write(buf) {
                        Ok(n) => n,
                        Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {
                            return Poll::Pending
                        }
                        Err(err) => return Poll::Ready(Err(err)),
                    };
                    if len != 0 {
                        data.extend_from_slice(&buf[..len]);
                        return Poll::Ready(Ok(len));
                    }
                }

                // complete handshake
                while stream.session.is_handshaking() {
                    ready!(stream.handshake(cx))?;
                }

                // write early data (fallback)
                if !stream.session.is_early_data_accepted() {
                    while *pos < data.len() {
                        let len = ready!(stream.as_mut_pin().poll_write(cx, &data[*pos..]))?;
                        *pos += len;
                    }
                }

                // end
                this.state = TlsState::Stream;
                stream.as_mut_pin().poll_write_vectored(cx, bufs)
            }
            _ => stream.as_mut_pin().poll_write_vectored(cx, bufs),
        };
        trace!(?write);
        write
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let _span = trace_span!("TlsStream::poll_flush", role = %"client", state = ?self.state);
        let this = self.get_mut();
        let mut stream =
            Stream::new(&mut this.io, &mut this.session).set_eof(!this.state.readable());

        #[cfg(feature = "early-data")]
        {
            if let TlsState::EarlyData(ref mut pos, ref mut data) = this.state {
                // complete handshake
                while stream.session.is_handshaking() {
                    ready!(stream.handshake(cx))?;
                }

                // write early data (fallback)
                if !stream.session.is_early_data_accepted() {
                    while *pos < data.len() {
                        let len = ready!(stream.as_mut_pin().poll_write(cx, &data[*pos..]))?;
                        *pos += len;
                    }
                }

                this.state = TlsState::Stream;
            }
        }

        let flush = stream.as_mut_pin().poll_flush(cx);
        trace!(?flush);
        flush
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let _span = trace_span!("TlsStream::poll_shutdown", role = %"client", state = ?self.state);
        if self.state.writeable() {
            trace!("sending close notify");
            self.session.send_close_notify();
            self.state.shutdown_write();
        }

        #[cfg(feature = "early-data")]
        {
            // we skip the handshake
            if let TlsState::EarlyData(..) = self.state {
                return Pin::new(&mut self.io).poll_shutdown(cx);
            }
        }

        let this = self.get_mut();
        let mut stream =
            Stream::new(&mut this.io, &mut this.session).set_eof(!this.state.readable());
        let shutdown = stream.as_mut_pin().poll_shutdown(cx);
        trace!(?shutdown);
        shutdown
    }

    fn is_write_vectored(&self) -> bool {
        self.io.is_write_vectored()
    }
}
