#!/usr/bin/env bash
set -e

# 1) Загружаем модули (если нужно) — в привилегированном контейнере modprobe сможет работать
modprobe nf_tables    || true
modprobe nfnetlink_queue || true

# 2) Очищаем старый набор правил и настраиваем nftables
nft flush ruleset

# Создаём таблицу inet filter
nft add table inet filter

# Добавляем цепочки prereouting и output, чтобы весь внешний трафик шёл в очередь
# Здесь мы предполагаем, что “внешний” трафик — всё, что вышло не на loopback или не на линковый интерфейс внутри контейнера.
# При необходимости можно уточнять «oifname != 'wg0'» и т.п.
nft 'add chain inet filter prerouting { type filter hook prerouting priority 0 ; }'
nft 'add chain inet filter output    { type filter hook output    priority 0 ; }'

# Правило: всё, что не локальный трафик (например, dst != 127.0.0.0/8), отправляем в NFQUEUE номер 0,
# где работает ваш nf_wgobfs-демон/пользовательское приложение (его вы запускаете отдельно на хосте или в контейнере).
# Если у вас nfqueue слушает не “0”, замените на нужный номер.
nft add rule inet filter prerouting ip saddr wg_server2 udp dport 51820 meta l4proto != udp queue num 0 bypass
nft add rule inet filter output ip daddr wg_sever2 udp sport 51820  meta l4proto != udp queue num 1 bypass

# 3) (Опционально) можно запустить какой-нибудь пользовательский демон `nf_wgobfs`, если он настроен в контейнере.
# Пример: если внутри контейнера у вас есть /usr/local/bin/nf_wgobfs-daemon, раскомментируйте:
/usr/local/bin/nf_wgobfs &

# 4) Теперь запускаем стандартный entrypoint linuxserver/wireguard — он сам поднимет /init и сам поднять wg0
exec /init
