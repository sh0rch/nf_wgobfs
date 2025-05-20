use crate::netutils::common::checksum16;

#[inline(always)]
pub fn clear_diffserv(packet: &mut [u8]) {
    if packet.len() >= 20 {
        let ecn = packet[1] & 0x03;
        packet[1] = ecn;
    }
}

#[inline(always)]
pub fn fix_udp_headers(packet: &mut [u8]) {
    if packet.len() < 20 {
        return;
    }
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    if ihl < 20 || ihl + 8 > packet.len() {
        return;
    }
    let total_len = packet.len() as u16;
    packet[2] = (total_len >> 8) as u8;
    packet[3] = (total_len & 0xff) as u8;

    packet[10] = 0;
    packet[11] = 0;
    let csum = checksum16(&packet[..ihl]);
    packet[10] = (csum >> 8) as u8;
    packet[11] = (csum & 0xff) as u8;

    let udp_len = (packet.len() - ihl) as u16;
    packet[ihl + 4] = (udp_len >> 8) as u8;
    packet[ihl + 5] = (udp_len & 0xff) as u8;

    packet[ihl + 6] = 0;
    packet[ihl + 7] = 0;
    let udp = &packet[ihl..];
    let src = &packet[12..16];
    let dst = &packet[16..20];
    let sum = udp_checksum(udp, src, dst);
    packet[ihl + 6] = (sum >> 8) as u8;
    packet[ihl + 7] = (sum & 0xff) as u8;
}

pub fn udp_checksum(udp: &[u8], src_ip: &[u8], dst_ip: &[u8]) -> u16 {
    const MAX_UDP: usize = 2048;
    let udp_len = udp.len();
    let pseudo_len = 12 + udp_len + (udp_len % 2);
    if udp_len <= MAX_UDP {
        let mut pseudo = [0u8; 12 + MAX_UDP + 1];
        pseudo[..4].copy_from_slice(src_ip);
        pseudo[4..8].copy_from_slice(dst_ip);
        pseudo[8] = 0;
        pseudo[9] = 17;
        pseudo[10] = (udp_len >> 8) as u8;
        pseudo[11] = (udp_len & 0xff) as u8;
        pseudo[12..12 + udp_len].copy_from_slice(udp);
        if udp_len % 2 != 0 {
            pseudo[12 + udp_len] = 0;
        }
        checksum16(&pseudo[..pseudo_len])
    } else {
        let mut pseudo = Vec::with_capacity(pseudo_len);
        pseudo.extend_from_slice(src_ip);
        pseudo.extend_from_slice(dst_ip);
        pseudo.push(0);
        pseudo.push(17);
        pseudo.push((udp_len >> 8) as u8);
        pseudo.push((udp_len & 0xff) as u8);
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
    fn test_clear_diffserv() {
        // DSCP = 0x2a, ECN = 0x01
        let mut packet = [
            0x45, 0x88, 0x00, 0xb0, 0x2e, 0x41, 0x00, 0x00, 0x40, 0x11, 0x81, 0x2f, 0x59, 0xdf,
            0x46, 0x63, 0xd5, 0xa5, 0x54, 0x5d, 0xca, 0x6c, 0xca, 0x6c, 0x00, 0x9c, 0x7b, 0x52,
            0x01,
        ];
        clear_diffserv(&mut packet);
        // После clear_diffserv должны остаться только 2 бита ECN
        assert_eq!(packet[1], 0x00);
    }

    #[test]
    fn test_fix_udp_headers_and_udp_checksum() {
        // Простейший IPv4+UDP пакет: 20 байт IP + 8 байт UDP + 4 байта данных
        let mut packet = [
            // IP header (20 байт)
            0x45, 0x00, 0x00, 0x1c, // Version/IHL, DSCP/ECN, Total Length (28)
            0x00, 0x00, 0x00, 0x00, // ID, Flags/Fragment Offset
            0x40, 0x11, 0x00, 0x00, // TTL, Protocol (UDP), Header Checksum
            192, 168, 1, 1, // Src IP
            192, 168, 1, 2, // Dst IP
            // UDP header (8 байт)
            0x12, 0x34, // Src port
            0x56, 0x78, // Dst port
            0x00, 0x0c, // Length (8+4)
            0x00, 0x00, // Checksum
            // Payload (4 байта)
            1, 2, 3, 4,
        ];

        let ihl = ((packet[0] & 0x0f) as usize) * 4;
        fix_udp_headers(&mut packet);
        let udp = &packet[ihl..];
        let src = &packet[12..16];
        let dst = &packet[16..20];
        // Скопировать UDP-заголовок и обнулить чек-сумму
        let mut udp_for_sum = udp.to_owned();
        udp_for_sum[6] = 0;
        udp_for_sum[7] = 0;

        let sum = udp_checksum(&udp_for_sum, src, dst);
        let packet_sum = ((packet[ihl + 6] as u16) << 8) | (packet[ihl + 7] as u16);

        assert_eq!(sum, packet_sum);
    }

    #[test]
    fn test_udp_checksum_even_and_odd() {
        let src = [10, 0, 0, 1];
        let dst = [10, 0, 0, 2];
        let udp_even = [0x00, 0x35, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00]; // 8 байт
        let udp_odd = [0x00, 0x35, 0x00, 0x35, 0x00, 0x07, 0x00, 0x00, 0xFF]; // 9 байт

        let sum_even = udp_checksum(&udp_even, &src, &dst);
        let sum_odd = udp_checksum(&udp_odd, &src, &dst);

        // Просто проверяем, что функция работает и возвращает не 0
        assert_ne!(sum_even, 0);
        assert_ne!(sum_odd, 0);
    }
}
