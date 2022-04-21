## Sniffer packetů - Projekt do IPK 2021/22, varianta ZETA
Síťový analyzátor v C++, který na určeném síťovém rozhraní
zachytává a filtruje pakety. Je nutno ho spouštět s rootovskými právy.


### Volání programu:

```
sudo ./ipk-sniffer {--help} [-i rozhraní | --interface rozhraní] {-p port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}'
```

V případě použítí --help dojde k vypsání nápovědy.  
**Tento argument nelze kombinovat s jinými argumenty**  

Při spuštění bez specifikace zachytávaných packetů se uvažuje stejná funkcionalita
jako při zadání všech, tedy _--tcp --udp --arp --icmp_. Jiné packety nejsou brány
v úvahu při žádném způsobu spuštění programu.

### Příklady spuštění:

```
./ipk-sniffer --help
```

```
sudo ./ipk-sniffer -i eth0
```

```
sudo ./ipk-sniffer -i
```

```
sudo ./ipk-sniffer -i eth0 --icmp -p 80
```


### Seznam odevzdaných souborů:

- ipk-sniffer.cpp  
- Makefile  
- manual.pdf  
- README.md
