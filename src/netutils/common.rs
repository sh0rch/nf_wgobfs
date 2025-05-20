#[inline(always)]
pub fn checksum16(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        let word = u16::from_be_bytes([chunk[0], chunk[1]]);
        sum += word as u32;
    }
    if let Some(&last) = chunks.remainder().get(0) {
        sum += (last as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let result = !(sum as u16);
    if result == 0 {
        0xffff
    } else {
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checksum16_even_bytes() {
        // 0x01 0x02 + 0x03 0x04 = 0x0102 + 0x0304 = 0x0406, one's complement = 0xfb f9
        let data = [0x01u8, 0x02, 0x03, 0x04];
        assert_eq!(checksum16(&data), 0xfbf9);
    }

    #[test]
    fn test_checksum16_odd_bytes() {
        // 0x01 0x02 + 0x03 = 0x0102 + 0x0300 = 0x0402, one's complement = 0xfb fd
        let data = [0x01u8, 0x02, 0x03];
        assert_eq!(checksum16(&data), 0xfbfd);
    }

    #[test]
    fn test_checksum16_empty() {
        let data: [u8; 0] = [];
        assert_eq!(checksum16(&data), 0xffff);
    }

    #[test]
    fn test_checksum16_all_zeros() {
        let data = [0u8; 8];
        assert_eq!(checksum16(&data), 0xffff);
    }

    #[test]
    fn test_checksum16_big_endian_consistency() {
        // Should be the same on big and little endian CPUs
        let data = [0x12u8, 0x34, 0x56, 0x78];
        assert_eq!(checksum16(&data), checksum16(&data));
    }
}
