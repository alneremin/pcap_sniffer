#!/bin/bash

INTERVAL=${1:-1}
OUTPUT=${2:-"../outputs/test/bt/output_$(date +%s).csv"}

echo "Interval: $INTERVAL seconds"
echo "Output file: $OUTPUT"

# mkdir -p "$(dirname "$OUTPUT")"

# Заголовок CSV
echo "timestamp_nsecs,total_bytes" > "$OUTPUT"

# Удаляем старый pipe, если существует
rm -f /tmp/btmon_pipe

# Запускаем btmon и пишем в pipe-файл
sudo btmon | while read line; do
    echo "$line" >> /tmp/btmon_pipe
done &
BTMON_PID=$!

echo "btmon PID: $BTMON_PID"

# Функция очистки при выходе
cleanup() {
    echo "Останавливаем btmon (PID: $BTMON_PID)"
    kill $BTMON_PID 2>/dev/null
    rm -f /tmp/btmon_pipe
    exit 0
}

trap cleanup SIGINT SIGTERM

prev_total=0

# Основной цикл
while true; do
    # Проверяем существование файла (Обратите внимание на пробелы!)
    if [ -f /tmp/btmon_pipe ]; then
        # Суммируем все dlen (и TX и RX)
        total=$(grep "Data" /tmp/btmon_pipe | grep "dlen" | grep -o 'dlen [0-9]*' | cut -d' ' -f2 | paste -sd+ | bc)
        
        # Если результат пустой, ставим 0
        total=${total:-0}
        diff=$((total-prev_total))
        # Получаем timestamp в наносекундах
        timestamp=$(date +%s%N)
        
        # Записываем в CSV
        echo "$timestamp,$diff" >> "$OUTPUT"
        
        # Показываем в консоли
        echo "[$(date +%H:%M:%S)] Всего байт: $diff"
  
  prev_total=$total
    else
        echo "Ожидание создания /tmp/btmon_pipe..."
    fi
    
    sleep $INTERVAL
done

# Этот код никогда не выполнится из-за бесконечного цикла,
# но cleanup обработает выход по Ctrl+C