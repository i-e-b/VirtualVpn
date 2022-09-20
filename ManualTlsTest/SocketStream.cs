using System.Net.Sockets;
using System.Text;

namespace ManualTlsTest;

/// <summary>
	/// Stream abstraction over a network socket
	/// </summary>
	public class SocketStream : Stream
	{
		Socket? _socket;

		/// <summary>
		/// Create a disconnected stream
		/// </summary>
		public SocketStream() { }

		/// <summary>
		/// Create a stream wrapper for a socket
		/// </summary>
		/// <param name="socket">socket to wrap</param>
		public SocketStream(Socket socket)
		{
			Console.WriteLine(nameof(SocketStream));
			_socket = socket;
		}

		/// <summary>
		/// Underlying socket used by this stream
		/// </summary>
		public Socket? Socket => _socket;

		/// <summary>
		/// Dispose of stream and socket.
		/// </summary>
		~SocketStream()
		{
			Console.WriteLine("~"+nameof(SocketStream));
			Dispose(false);
		}

		/// <summary>
		/// Releases the unmanaged resources used by the <see cref="T:System.IO.Stream"/> and optionally releases the managed resources.
		/// </summary>
		protected override void Dispose(bool disposing)
		{
			Console.WriteLine(nameof(Dispose));
			var sock = Interlocked.Exchange(ref _socket, null);
			if (sock == null) return;
			if (sock.Connected)
			{
				sock.Disconnect(false);
			}
			sock.Dispose();
			base.Dispose(disposing);
		}

		/// <summary> Does nothing </summary>
		public override void Flush() { 
			Console.WriteLine(nameof(Flush));
		}

		/// <summary>
		/// Reads from the underlying socket into a provided buffer.
		/// </summary>
		/// <returns>
		/// The total number of bytes read into the buffer. This can be less than the number of bytes requested if that many bytes are not currently available, or zero (0) if the end of the stream has been reached.
		/// </returns>
		/// <param name="buffer">An array of bytes. When this method returns, the buffer contains the specified byte array with the values between <paramref name="offset"/> and (<paramref name="offset"/> + <paramref name="count"/> - 1) replaced by the bytes read from the current source. </param><param name="offset">The zero-based byte offset in <paramref name="buffer"/> at which to begin storing the data read from the current stream. </param><param name="count">The maximum number of bytes to be read from the current stream. </param><exception cref="T:System.ArgumentException">The sum of <paramref name="offset"/> and <paramref name="count"/> is larger than the buffer length. </exception><exception cref="T:System.ArgumentNullException"><paramref name="buffer"/> is null. </exception><exception cref="T:System.ArgumentOutOfRangeException"><paramref name="offset"/> or <paramref name="count"/> is negative. </exception><exception cref="T:System.IO.IOException">An I/O error occurs. </exception><exception cref="T:System.NotSupportedException">The stream does not support reading. </exception><exception cref="T:System.ObjectDisposedException">Methods were called after the stream was closed. </exception><filterpriority>1</filterpriority>
		public override int Read(byte[] buffer, int offset, int count)
		{
			Console.WriteLine($"{nameof(Read)}(buffer[{buffer.Length}], offset={offset}, count={count})");
            if (_socket == null) throw new InvalidOperationException("Attempted to read from a disconnected socket");
            
            Thread.Sleep(250);
            var len = _socket.Receive(buffer, offset, count, SocketFlags.None, out var err);
			if (err != SocketError.Success && err != SocketError.WouldBlock)
			{
				if (err == SocketError.TimedOut)
					throw new TimeoutException();
				throw new SocketException((int) err);
			}
			Console.WriteLine($"    {nameof(Read)} got {len} bytes; err={err.ToString()}");
			Console.WriteLine(string.Join(" ", buffer.Take(512).Select(b=>b.ToString("x2"))));
			Console.WriteLine(Encoding.UTF8.GetString(buffer, offset, len));
			
			Position += len;
			return len;
		}

		/// <summary>
		/// Writes a sequence of bytes to the underlying socket.
		/// </summary>
		/// <param name="buffer">An array of bytes. This method copies <paramref name="count"/> bytes from <paramref name="buffer"/> to the current stream. </param><param name="offset">The zero-based byte offset in <paramref name="buffer"/> at which to begin copying bytes to the current stream. </param><param name="count">The number of bytes to be written to the current stream. </param><filterpriority>1</filterpriority>
		public override void Write(byte[] buffer, int offset, int count)
		{
			Console.WriteLine(nameof(Write));
            if (_socket == null) throw new InvalidOperationException("Attempted to read from a disconnected socket");
            _socket.Send(buffer, offset, count, SocketFlags.None, out var err);
			if (err != SocketError.Success)
			{
				if (err == SocketError.TimedOut)
					throw new TimeoutException();
				throw new SocketException((int)err);
			}
			_writtenLength += count;
		}

		/// <summary>
		/// Sets read and write counts (Position, Length) to 0
		/// </summary>
		public void ResetCounts()
		{
			_writtenLength = 0;
			Position = 0;
		}

		long _writtenLength;
		private long _position;

		/// <summary>
		/// Number of bytes written to socket
		/// </summary>
		public override long Length { get { 
			Console.WriteLine(nameof(Length));
			return _writtenLength; 
		} }

		/// <summary>
		/// Number of bytes read from socket
		/// </summary>
		public override long Position
		{
			get { 
				Console.WriteLine("get "+nameof(Position));
				return _position;
			}
			set { 
				Console.WriteLine("set "+nameof(Position));
				_position = value;
			}
		}

		/// <summary> No action </summary>
		public override long Seek(long offset, SeekOrigin origin) {
			
			Console.WriteLine(nameof(Seek));
			return 0;
		}
        /// <summary> No action </summary>
		public override void SetLength(long value) {  }

        /// <summary> No action </summary>
        public override bool CanRead
        {
	        get
	        {
		        Console.WriteLine(nameof(CanRead));
		        return true;
	        }
        }

        /// <summary> No action </summary>
        public override bool CanSeek
        {
	        get
	        {
		        Console.WriteLine(nameof(CanSeek));
		        return false;
	        }
        }

        /// <summary> No action </summary>
        public override bool CanWrite
        {
	        get
	        {
		        Console.WriteLine(nameof(CanWrite));
		        return true;
	        }
        }
	}