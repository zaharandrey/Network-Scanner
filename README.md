Визначення активних хостів у заданому діапазоні IP-адрес.
Сканування відкритих портів.
Визначення сервісів та їхніх версій.
Реалізація:
Сканування мережі:
Використовуємо бібліотеку socket для підключення до портів.
Використовуємо scapy для ARP-сканування активних хостів.
Визначення сервісів:
Підключення до відкритих портів і зчитування банерів.
Інтеграція:
Збереження результатів у файл або базу даних.
Генерація правил для брандмауера на основі отриманих даних.
