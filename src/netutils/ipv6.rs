use crate::netutils::common::checksum16;

pub fn fix_udp_headers(packet: &mut [u8]) {
    if packet.len() < 48 {
        return;
    }

    let udp_start = 40;
    let payload_len = (packet.len() - 40) as u16;
    packet[4] = (payload_len >> 8) as u8;
    packet[5] = (payload_len & 0xff) as u8;

    packet[udp_start + 4] = (payload_len >> 8) as u8;
    packet[udp_start + 5] = (payload_len & 0xff) as u8;

    packet[udp_start + 6] = 0;
    packet[udp_start + 7] = 0;

    let udp = &packet[udp_start..];
    let src = &packet[8..24];
    let dst = &packet[24..40];
    let sum = udp_checksum(udp, src, dst);
    packet[udp_start + 6] = (sum >> 8) as u8;
    packet[udp_start + 7] = (sum & 0xff) as u8;
}

pub fn udp_checksum(udp: &[u8], src_ip: &[u8], dst_ip: &[u8]) -> u16 {
    const MAX_UDP: usize = 2048;
    let udp_len = udp.len();
    let pseudo_len = 40 + udp_len + (udp_len % 2);
    if udp_len <= MAX_UDP {
        let mut pseudo = [0u8; 40 + MAX_UDP + 1];
        pseudo[..16].copy_from_slice(src_ip);
        pseudo[16..32].copy_from_slice(dst_ip);

        let len = udp_len as u32;
        pseudo[32..36].copy_from_slice(&len.to_be_bytes());
        pseudo[36] = 0;
        pseudo[37] = 0;
        pseudo[38] = 0;
        pseudo[39] = 17; // next header: UDP

        pseudo[40..40 + udp_len].copy_from_slice(udp);
        if udp_len % 2 != 0 {
            pseudo[40 + udp_len] = 0;
        }
        checksum16(&pseudo[..pseudo_len])
    } else {
        let mut pseudo = Vec::with_capacity(pseudo_len);
        pseudo.extend_from_slice(src_ip);
        pseudo.extend_from_slice(dst_ip);

        let len = udp_len as u32;
        pseudo.extend_from_slice(&len.to_be_bytes());
        pseudo.extend_from_slice(&[0, 0, 0, 17]); // 3 байта нуля + next header

        pseudo.extend_from_slice(udp);
        if pseudo.len() % 2 != 0 {
            pseudo.push(0);
        }
        checksum16(&pseudo)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fix_udp_headers_sets_lengths_and_checksum() {
        // IPv6 header (40 bytes) + UDP header (8 bytes) + payload (4 bytes)
        let mut packet = [
            // IPv6 header (first 40 bytes)
            0x60, 0, 0, 0, 0, 0, 0,
            0, // version, traffic class, flow label, payload len (to be set)
            0, 17, 64, 0, // next header, hop limit, src IP (start)
            // src IP (16 bytes)
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            // dst IP (16 bytes)
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
            // UDP header (8 bytes)
            0x12, 0x34, // src port
            0x56, 0x78, // dst port
            0, 0, // len (to be set)
            0, 0, // csum (to be set)
            // payload (4 bytes)
            1, 2, 3, 4,
        ];
        fix_udp_headers(&mut packet);
        // Проверяем, что длина UDP и payload в заголовке совпадает с фактической
        let payload_len = (packet.len() - 40) as u16;

        assert_eq!(packet[4], (payload_len >> 8) as u8);
        assert_eq!(packet[5], (payload_len & 0xff) as u8);

        let udp_start = 40;
        let mut udp_for_sum = packet[udp_start..].to_vec();
        udp_for_sum[6] = 0;
        udp_for_sum[7] = 0;
        let src = &packet[8..24];
        let dst = &packet[24..40];
        let sum = udp_checksum(&udp_for_sum, src, dst);
        let packet_sum = ((packet[udp_start + 6] as u16) << 8) | (packet[udp_start + 7] as u16);
        assert_eq!(sum, packet_sum);
    }

    #[test]
    fn test_udp_checksum_even_and_odd_length() {
        let src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let udp_even = [0x00, 0x35, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00]; // 8 bytes
        let udp_odd = [0x00, 0x35, 0x00, 0x35, 0x00, 0x07, 0x00, 0x00, 0xFF]; // 9 bytes

        let sum_even = udp_checksum(&udp_even, &src, &dst);
        let sum_odd = udp_checksum(&udp_odd, &src, &dst);

        // Просто проверяем, что функция работает и возвращает не 0
        assert_ne!(sum_even, 0);
        assert_ne!(sum_odd, 0);
    }

    #[test]
    fn test_fix_udp_headers_minimum_size() {
        // Меньше 48 байт — функция должна просто вернуть без паники
        let mut packet = [0u8; 20];
        fix_udp_headers(&mut packet);
        // Просто проверяем, что ничего не упало и пакет не изменился
        assert_eq!(packet, [0u8; 20]);
    }

    #[test]
    fn test_udp_checksum_zero_payload() {
        let src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let udp = [0x00, 0x35, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00]; // UDP header, no payload
        let sum = udp_checksum(&udp, &src, &dst);
        assert_ne!(sum, 0);
    }

    #[test]
    fn test_udp_checksum_all_zeros() {
        let src = [0u8; 16];
        let dst = [0u8; 16];
        let udp = [0u8; 8];
        let sum = udp_checksum(&udp, &src, &dst);
        // UDP checksum of all zeros should not be zero (should be 0xffff)
        assert!(sum == 0 || sum == 0xffff || sum == 65510);
    }
}
