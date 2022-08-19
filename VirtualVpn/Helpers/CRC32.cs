using System.Security.Cryptography;

namespace VirtualVpn.Helpers {

	/// <summary>
	/// CRC32
	/// </summary>
	public class Crc32 : HashAlgorithm
	{
		public const UInt32 DefaultPolynomial = 0x04c11db7;//the same as  0xedb88320  "reversed"?
		public const UInt32 DefaultSeed = 0xffffffff;

		private UInt32 _hash;
		private readonly UInt32 _seed;
		private readonly uint[] _table;
		private static uint[]? _defaultTable;

		public Crc32()
		{
			_table = InitializeTable(DefaultPolynomial);
			_seed = DefaultSeed;
			Initialize();
		}
		public override int HashSize => 32;
		public sealed override void Initialize(){_hash = _seed;}
		protected override void HashCore(byte[] buffer, int start, int length)
		{
			_hash = CalculateHash(_table, _hash, buffer, start, length);
		}

		protected override byte[] HashFinal()
		{
			var hashBuffer = UInt32ToBigEndianBytes(~_hash);
			HashValue = hashBuffer;
			return hashBuffer;
		}

		public static UInt32 Compute(byte[] buffer)
		{
			return ~CalculateHash(InitializeTable(DefaultPolynomial), DefaultSeed, buffer, 0, buffer.Length);
		}

		public static UInt32 Compute(UInt32 seed, byte[] buffer)
		{
			return ~CalculateHash(InitializeTable(DefaultPolynomial), seed, buffer, 0, buffer.Length);
		}

		public static UInt32 Compute(UInt32 polynomial, UInt32 seed, byte[] buffer)
		{
			return ~CalculateHash(InitializeTable(polynomial), seed, buffer, 0, buffer.Length);
		}

		private static uint[] InitializeTable(UInt32 polynomial)
		{
			if (polynomial == DefaultPolynomial && _defaultTable != null) return _defaultTable;

			var createTable = new UInt32[256];
			for (int i = 0; i < 256; i++)
			{
				var entry = (UInt32)i;
				for (int j = 0; j < 8; j++) entry = (entry & 1) == 1 ? (entry >> 1) ^ polynomial : entry >> 1;
				createTable[i] = entry;
			}

			if (polynomial == DefaultPolynomial) _defaultTable = createTable;
			return createTable;
		}

		private static UInt32 CalculateHash(uint[] table, UInt32 seed, byte[] buffer, int start, int size)
		{
			var crc = seed;
			for (int i = start; i < size; i++)
				unchecked
				{
					crc = (crc >> 8) ^ table[buffer[i] ^ crc & 0xff];
				}
			return crc;
		}

		private static byte[] UInt32ToBigEndianBytes(UInt32 x)
		{
			return new[] {
				(byte)((x >> 24) & 0xff),
				(byte)((x >> 16) & 0xff),
				(byte)((x >> 8) & 0xff),
				(byte)(x & 0xff)
			};
		}
	}
}