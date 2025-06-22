#!/bin/bash
# ===============================================================================
# Script: informe_sistema_completo.sh
# Autor: Sistema de Análisis Profundo de Infraestructura
# Versión: 2.0
# Descripción: Generador de informes técnicos exhaustivos para análisis forense
# Compatibilidad: Linux (Ubuntu/Debian/CentOS/RHEL/Rocky/AlmaLinux)
# Dependencias: lshw, dmidecode, ethtool, ss, lsof, iostat, vmstat
# ===============================================================================

# ===============================================================================
# CONFIGURACIÓN GLOBAL Y CONSTANTES
# ===============================================================================

# Colores para salida en terminal
readonly ROJO='\033[0;31m'
readonly VERDE='\033[0;32m'
readonly AMARILLO='\033[1;33m'
readonly AZUL='\033[0;34m'
readonly MAGENTA='\033[0;35m'
readonly CIAN='\033[0;36m'
readonly BLANCO='\033[1;37m'
readonly GRIS='\033[0;37m'
readonly RESET='\033[0m'

# Configuración de archivos y directorios
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly OUTPUT_DIR="${SCRIPT_DIR}/reportes_sistema"
readonly TEMP_DIR="/tmp/sistema_analisis_$"
readonly LOG_FILE="${OUTPUT_DIR}/generacion_reportes.log"

# Metadatos del sistema
readonly TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
readonly HOSTNAME=$(hostname)
readonly KERNEL_VERSION=$(uname -r)
readonly OS_INFO=$(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d'"' -f2 || echo "Desconocido")

# ===============================================================================
# FUNCIONES DE UTILIDAD Y CONFIGURACIÓN
# ===============================================================================

# Función para inicializar directorios y verificar permisos
inicializar_entorno() {
    # Crear estructura de directorios
    mkdir -p "$OUTPUT_DIR" "$TEMP_DIR" 2>/dev/null
    
    # Verificar permisos de escritura
    if [[ ! -w "$OUTPUT_DIR" ]]; then
        echo -e "${ROJO}❌ Error: Sin permisos de escritura en $OUTPUT_DIR${RESET}" >&2
        return 1
    fi
    
    # Crear archivo de log si no existe
    touch "$LOG_FILE" 2>/dev/null
    
    return 0
}

# Función de logging con diferentes niveles
escribir_log() {
    local nivel="$1"
    local mensaje="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo "[$timestamp] [$nivel] $mensaje" >> "$LOG_FILE" 2>/dev/null
    
    # También mostrar en pantalla según el nivel
    case "$nivel" in
        "ERROR")   echo -e "${ROJO}❌ $mensaje${RESET}" >&2 ;;
        "WARNING") echo -e "${AMARILLO}⚠️  $mensaje${RESET}" ;;
        "INFO")    echo -e "${AZUL}ℹ️  $mensaje${RESET}" ;;
        "SUCCESS") echo -e "${VERDE}✅ $mensaje${RESET}" ;;
        *)         echo -e "${GRIS}🔹 $mensaje${RESET}" ;;
    esac
}

# Función para verificar dependencias opcionales
verificar_dependencias() {
    local dependencias_opcionales=("lshw" "dmidecode" "ethtool" "iostat" "vmstat" "lsof" "smartctl")
    local disponibles=()
    local faltantes=()
    
    for dep in "${dependencias_opcionales[@]}"; do
        if command -v "$dep" &> /dev/null; then
            disponibles+=("$dep")
        else
            faltantes+=("$dep")
        fi
    done
    
    escribir_log "INFO" "Dependencias disponibles: ${disponibles[*]}"
    if [[ ${#faltantes[@]} -gt 0 ]]; then
        escribir_log "WARNING" "Dependencias faltantes (funcionalidad limitada): ${faltantes[*]}"
    fi
}

# Función para ejecutar comandos de forma segura
ejecutar_comando() {
    local comando="$1"
    local descripcion="$2"
    local salida_archivo="$3"
    
    escribir_log "DEBUG" "Ejecutando: $comando"
    
    if eval "$comando" > "$salida_archivo" 2>/dev/null; then
        return 0
    else
        echo "Error ejecutando: $descripcion" > "$salida_archivo"
        escribir_log "WARNING" "Fallo en comando: $descripcion"
        return 1
    fi
}

# ===============================================================================
# FUNCIONES DE ANÁLISIS DEL SISTEMA
# ===============================================================================

# Información básica del sistema y hardware
generar_info_sistema() {
    cat << EOF
# ===============================================================================
# INFORMACIÓN GENERAL DEL SISTEMA
# ===============================================================================

## 🖥️ IDENTIFICACIÓN DEL SISTEMA
Hostname: $HOSTNAME
Fecha de generación: $(date '+%A, %d de %B de %Y - %H:%M:%S %Z')
Usuario que ejecuta: $(whoami)
Directorio de trabajo: $(pwd)

## 🧠 INFORMACIÓN DEL SISTEMA OPERATIVO
Sistema Operativo: $OS_INFO
Kernel: $KERNEL_VERSION
Arquitectura: $(uname -m)
Versión del Kernel: $(uname -v)
Distribución: $(lsb_release -d 2>/dev/null | cut -f2 || cat /etc/issue | head -1 | tr -d '\n\r' || echo "No disponible")

## ⏱️ TIEMPO Y ZONA HORARIA
Uptime del sistema: $(uptime -p 2>/dev/null || uptime)
Zona horaria: $(timedatectl show --property=Timezone --value 2>/dev/null || date +%Z)
Fecha de último reinicio: $(who -b 2>/dev/null | awk '{print $3, $4}' || echo "No disponible")

## 👤 INFORMACIÓN DE USUARIOS
Usuario actual: $(id)
Usuarios conectados actualmente:
$(who -u 2>/dev/null || w)

Últimos logins:
$(last -n 10 2>/dev/null | head -10)

## 🔐 INFORMACIÓN DE SEGURIDAD BÁSICA
Usuarios con UID 0 (root): $(awk -F: '$3==0 {print $1}' /etc/passwd | tr '\n' ' ')
Usuarios con shell válido: $(grep -E '/bin/(bash|sh|zsh|fish) /etc/passwd | wc -l)
Cuentas bloqueadas: $(passwd -Sa 2>/dev/null | grep -c " L " || echo "No disponible")

EOF
}

# Análisis detallado de hardware
generar_info_hardware() {
    local hardware_file="$TEMP_DIR/hardware_info.txt"
    
    cat << EOF
# ===============================================================================
# ANÁLISIS DETALLADO DE HARDWARE
# ===============================================================================

## 🔧 PROCESADOR (CPU)
$(cat /proc/cpuinfo | grep -E '^(processor|model name|cpu MHz|cache size|cpu cores|siblings|physical id)' | head -20)

Número total de núcleos lógicos: $(nproc)
Número de núcleos físicos: $(grep -c ^processor /proc/cpuinfo)
Frecuencia actual: $(cat /proc/cpuinfo | grep "cpu MHz" | head -1 | awk '{print $4}') MHz

## 💾 MEMORIA DEL SISTEMA
$(free -h)

Información detallada de memoria:
$(cat /proc/meminfo | head -20)

## 🗄️ INFORMACIÓN DE ALMACENAMIENTO
### Dispositivos de bloque:
$(lsblk -f 2>/dev/null || lsblk)

### Uso de espacio en disco:
$(df -h)

### Información de montajes:
$(mount | grep -E '^/dev/' | sort)

### Análisis de inodos:
$(df -i | grep -E '^/dev/')

EOF

    # Información de hardware detallada (si lshw está disponible)
    if command -v lshw &> /dev/null && [[ $EUID -eq 0 ]]; then
        echo "## 🔍 INFORMACIÓN DETALLADA DE HARDWARE (LSHW)"
        lshw -short 2>/dev/null || echo "Error ejecutando lshw o permisos insuficientes"
        echo ""
    fi
    
    # Información DMI (si dmidecode está disponible)
    if command -v dmidecode &> /dev/null && [[ $EUID -eq 0 ]]; then
        echo "## 🖥️ INFORMACIÓN DMI DEL SISTEMA"
        echo "### Información del BIOS:"
        dmidecode -t bios 2>/dev/null | grep -E "(Vendor|Version|Release Date)"
        echo ""
        echo "### Información de la placa base:"
        dmidecode -t baseboard 2>/dev/null | grep -E "(Manufacturer|Product Name|Version)"
        echo ""
    fi
    
    # Información de dispositivos PCI y USB
    echo "## 🔌 DISPOSITIVOS CONECTADOS"
    echo "### Dispositivos PCI:"
    lspci 2>/dev/null | head -20
    echo ""
    echo "### Dispositivos USB:"
    lsusb 2>/dev/null
    echo ""
}

# Análisis exhaustivo de red y conectividad
generar_info_red() {
    cat << EOF
# ===============================================================================
# ANÁLISIS COMPLETO DE RED Y CONECTIVIDAD
# ===============================================================================

## 🌐 CONFIGURACIÓN DE INTERFACES DE RED
$(ip addr show 2>/dev/null)

## 🔗 TABLA DE ENRUTAMIENTO
$(ip route show 2>/dev/null)

## 🏠 TABLA ARP (Dispositivos en red local)
$(ip neigh show 2>/dev/null)

## 🔍 RESOLUCIÓN DNS
Servidores DNS configurados:
$(cat /etc/resolv.conf 2>/dev/null | grep nameserver)

## 🌍 CONECTIVIDAD EXTERNA
Test de conectividad a Internet:
$(ping -c 4 8.8.8.8 2>/dev/null | tail -2 || echo "Error en test de conectividad")

Test de resolución DNS:
$(nslookup google.com 2>/dev/null | head -10 || echo "Error en resolución DNS")

## 🔐 PUERTOS Y SERVICIOS ACTIVOS
### Puertos en escucha:
$(ss -tuln 2>/dev/null | head -20)

### Conexiones establecidas:
$(ss -tun state established 2>/dev/null | head -15)

EOF

    # Análisis de interfaces con ethtool (si está disponible)
    if command -v ethtool &> /dev/null; then
        echo "## ⚡ INFORMACIÓN DETALLADA DE INTERFACES ETHERNET"
        for iface in $(ls /sys/class/net/ | grep -E '^(eth|ens|enp)'); do
            if [[ -e "/sys/class/net/$iface/operstate" ]]; then
                echo "### Interfaz: $iface"
                ethtool "$iface" 2>/dev/null | grep -E "(Speed|Duplex|Link detected)" || echo "No disponible"
                echo ""
            fi
        done
    fi
    
    # Estadísticas de red
    echo "## 📊 ESTADÍSTICAS DE TRÁFICO DE RED"
    cat /proc/net/dev | column -t
    echo ""
}

# Análisis de procesos y rendimiento
generar_info_procesos() {
    cat << EOF
# ===============================================================================
# ANÁLISIS DE PROCESOS Y RENDIMIENTO DEL SISTEMA
# ===============================================================================

## 🔄 PROCESOS ACTIVOS Y CARGA DEL SISTEMA
Carga promedio del sistema: $(uptime | awk -F'load average:' '{print $2}')
Total de procesos: $(ps aux --no-headers | wc -l)
Procesos en ejecución: $(ps aux --no-headers | awk '$8 ~ /^R/ {count++} END {print count+0}')
Procesos dormidos: $(ps aux --no-headers | awk '$8 ~ /^S/ {count++} END {print count+0}')
Procesos zombie: $(ps aux --no-headers | awk '$8 ~ /^Z/ {count++} END {print count+0}')

## 🏆 TOP 15 PROCESOS POR USO DE CPU
$(ps -eo pid,ppid,cmd,pcpu,pmem --sort=-pcpu --no-headers | head -15)

## 💾 TOP 15 PROCESOS POR USO DE MEMORIA
$(ps -eo pid,ppid,cmd,pcpu,pmem --sort=-pmem --no-headers | head -15)

## ⚡ PROCESOS CON MAYOR TIEMPO DE CPU
$(ps -eo pid,ppid,cmd,time --sort=-time --no-headers | head -10)

## 🔍 ANÁLISIS DE HILOS (THREADS)
Total de hilos en el sistema: $(cat /proc/loadavg | awk '{print $4}' | cut -d'/' -f2)

EOF

    # Análisis con vmstat si está disponible
    if command -v vmstat &> /dev/null; then
        echo "## 📈 ESTADÍSTICAS DE MEMORIA VIRTUAL (VMSTAT)"
        vmstat 1 5 2>/dev/null || echo "Error ejecutando vmstat"
        echo ""
    fi
    
    # Análisis de archivos abiertos si lsof está disponible
    if command -v lsof &> /dev/null; then
        echo "## 📁 ARCHIVOS ABIERTOS MÁS COMUNES"
        lsof 2>/dev/null | awk '{print $1}' | sort | uniq -c | sort -nr | head -10
        echo ""
        
        echo "## 🌐 CONEXIONES DE RED ACTIVAS (LSOF)"
        lsof -i 2>/dev/null | head -15
        echo ""
    fi
}

# Análisis de servicios del sistema
generar_info_servicios() {
    cat << EOF
# ===============================================================================
# ANÁLISIS DE SERVICIOS Y DEMONIOS DEL SISTEMA
# ===============================================================================

## 🔄 SERVICIOS SYSTEMD ACTIVOS
$(systemctl list-units --type=service --state=active --no-legend 2>/dev/null | head -20)

## ⚠️ SERVICIOS FALLIDOS
$(systemctl list-units --type=service --state=failed --no-legend 2>/dev/null)

## 🚀 SERVICIOS HABILITADOS AL INICIO
$(systemctl list-unit-files --type=service --state=enabled --no-legend 2>/dev/null | head -15)

## 🔧 PROCESOS INIT Y KERNEL
$(ps -ef | grep -E '\[.*\] | head -10)

## 🕒 TAREAS PROGRAMADAS (CRON)
### Crontab del sistema:
$(cat /etc/crontab 2>/dev/null || echo "No accesible")

### Tareas en /etc/cron.d/:
$(ls -la /etc/cron.d/ 2>/dev/null || echo "Directorio no accesible")

EOF

    # Análisis de timers de systemd
    if systemctl list-timers &> /dev/null; then
        echo "## ⏰ TIMERS DE SYSTEMD"
        systemctl list-timers --no-legend 2>/dev/null | head -10
        echo ""
    fi
}

# ===============================================================================
# NUEVAS FUNCIONES AVANZADAS DE ANÁLISIS
# ===============================================================================

# 1. Análisis forense de seguridad y logs
generar_analisis_seguridad() {
    cat << EOF
# ===============================================================================
# ANÁLISIS FORENSE DE SEGURIDAD Y AUDITORÍA
# ===============================================================================

## 🔐 ANÁLISIS DE AUTENTICACIÓN
### Últimos intentos de login exitosos:
$(last -n 15 2>/dev/null)

### Intentos de login fallidos (últimas 50 líneas):
EOF

    # Analizar logs de autenticación según la distribución
    if [[ -f /var/log/auth.log ]]; then
        echo "$(tail -50 /var/log/auth.log 2>/dev/null | grep -i 'failed\|invalid\|error' | tail -10)"
    elif [[ -f /var/log/secure ]]; then
        echo "$(tail -50 /var/log/secure 2>/dev/null | grep -i 'failed\|invalid\|error' | tail -10)"
    else
        echo "Logs de autenticación no accesibles"
    fi
    
    cat << EOF

## 🛡️ ANÁLISIS DE PERMISOS Y ARCHIVOS CRÍTICOS
### Archivos con permisos problemáticos (777):
$(find /etc /usr/bin /usr/sbin -maxdepth 2 -perm 777 -type f 2>/dev/null | head -10 || echo "Ninguno encontrado o sin permisos")

### Archivos SUID peligrosos:
$(find /usr/bin /usr/sbin /bin /sbin -perm -4000 -type f 2>/dev/null | head -10)

### Verificación de integridad de archivos críticos:
Permisos de /etc/passwd: $(ls -l /etc/passwd 2>/dev/null | awk '{print $1,$3,$4}')
Permisos de /etc/shadow: $(ls -l /etc/shadow 2>/dev/null | awk '{print $1,$3,$4}')
Permisos de /etc/sudoers: $(ls -l /etc/sudoers 2>/dev/null | awk '{print $1,$3,$4}')

## 🚨 ANÁLISIS DE PROCESOS SOSPECHOSOS
### Procesos ejecutándose como root:
$(ps -eo pid,user,cmd | grep '^[[:space:]]*[0-9]*[[:space:]]*root' | head -10)

### Procesos con nombres inusuales:
$(ps -eo pid,cmd | grep -E '\.(tmp|temp|cache)|\-\-' | head -5 || echo "Ninguno detectado")

EOF
}

# 2. Análisis de rendimiento e I/O
generar_analisis_rendimiento() {
    cat << EOF
# ===============================================================================
# ANÁLISIS PROFUNDO DE RENDIMIENTO E I/O
# ===============================================================================

## 📊 ESTADÍSTICAS DE CPU Y CARGA
Load Average (1, 5, 15 min): $(cat /proc/loadavg | awk '{print $1, $2, $3}')
Número de núcleos: $(nproc)
Relación carga/núcleos: $(awk "BEGIN {printf \"%.2f\", $(cat /proc/loadavg | awk '{print $1}')/$(nproc)}")

### Información de frecuencia de CPU:
$(cat /proc/cpuinfo | grep "cpu MHz" | head -4)

## 💾 ANÁLISIS DETALLADO DE MEMORIA
$(cat /proc/meminfo | grep -E "(MemTotal|MemFree|MemAvailable|Buffers|Cached|SwapTotal|SwapFree|Dirty|Writeback)")

### Fragmentación de memoria:
$(grep -E "(Node|DMA|Normal|HighMem)" /proc/buddyinfo 2>/dev/null | head -5 || echo "Información no disponible")

## 🗄️ ANÁLISIS DE I/O DE DISCO
### Estadísticas generales de I/O:
$(cat /proc/diskstats | awk '{print $3, $4, $8}' | head -10)

EOF

    # Análisis con iostat si está disponible
    if command -v iostat &> /dev/null; then
        echo "### Estadísticas detalladas de I/O (iostat):"
        iostat -x 1 3 2>/dev/null | tail -20 || echo "Error ejecutando iostat"
        echo ""
    fi
    
    cat << EOF
## 🔄 ANÁLISIS DE CONTEXTO DE INTERRUPCIONES
$(cat /proc/interrupts | head -10)

### Cambios de contexto:
$(grep ctxt /proc/stat)

## 🌡️ INFORMACIÓN DE TEMPERATURA Y SENSORES
EOF

    # Información de temperatura
    if command -v sensors &> /dev/null; then
        sensors 2>/dev/null || echo "Sensores no disponibles"
    elif [[ -d /sys/class/thermal ]]; then
        echo "Temperaturas de zonas térmicas:"
        for zone in /sys/class/thermal/thermal_zone*/temp; do
            if [[ -r "$zone" ]]; then
                local temp=$(cat "$zone")
                local zone_name=$(basename $(dirname "$zone"))
                echo "$zone_name: $((temp/1000))°C"
            fi
        done
    else
        echo "Información de temperatura no disponible"
    fi
    
    echo ""
}

# 3. Inventario completo de software
generar_inventario_software() {
    cat << EOF
# ===============================================================================
# INVENTARIO COMPLETO DE SOFTWARE Y PAQUETES
# ===============================================================================

## 📦 GESTORES DE PAQUETES Y SOFTWARE INSTALADO

EOF

    # Detectar gestor de paquetes y listar software
    if command -v dpkg &> /dev/null; then
        echo "### Paquetes instalados (APT/DPKG) - Últimos 20:"
        dpkg -l | tail -20
        echo ""
        echo "Total de paquetes instalados: $(dpkg -l | grep -c '^ii')"
    elif command -v rpm &> /dev/null; then
        echo "### Paquetes instalados (RPM) - Últimos 20:"
        rpm -qa | tail -20
        echo ""
        echo "Total de paquetes instalados: $(rpm -qa | wc -l)"
    elif command -v pacman &> /dev/null; then
        echo "### Paquetes instalados (Pacman) - Últimos 20:"
        pacman -Q | tail -20
        echo ""
        echo "Total de paquetes instalados: $(pacman -Q | wc -l)"
    fi
    
    cat << EOF

## 🐍 ENTORNOS DE DESARROLLO
### Python instalado:
$(python3 --version 2>/dev/null || echo "Python3 no disponible")
$(python --version 2>/dev/null || echo "Python2 no disponible")

### Node.js y npm:
$(node --version 2>/dev/null || echo "Node.js no disponible")
$(npm --version 2>/dev/null || echo "npm no disponible")

### Otros lenguajes:
$(java -version 2>&1 | head -1 || echo "Java no disponible")
$(gcc --version 2>/dev/null | head -1 || echo "GCC no disponible")
$(go version 2>/dev/null || echo "Go no disponible")

## 🔧 HERRAMIENTAS DE SISTEMA
### Editores disponibles:
$(which vim nano emacs 2>/dev/null | tr '\n' ' ' || echo "Ninguno de los editores comunes encontrado")

### Herramientas de red:
$(which curl wget netcat ss netstat 2>/dev/null | tr '\n' ' ')

### Herramientas de monitoreo:
$(which htop top iotop nethogs 2>/dev/null | tr '\n' ' ')

EOF
}

# 4. Análisis de configuración del sistema
generar_analisis_configuracion() {
    cat << EOF
# ===============================================================================
# ANÁLISIS DE CONFIGURACIÓN DEL SISTEMA
# ===============================================================================

## ⚙️ CONFIGURACIÓN DEL KERNEL
### Parámetros del kernel (sysctl):
$(sysctl -a 2>/dev/null | grep -E "(net.core|vm.swappiness|kernel.hostname)" | head -10)

### Módulos del kernel cargados (primeros 15):
$(lsmod | head -15)

## 🌐 CONFIGURACIÓN DE RED AVANZADA
### Configuración de firewall (iptables):
EOF

    if command -v iptables &> /dev/null && [[ $EUID -eq 0 ]]; then
        iptables -L -n 2>/dev/null | head -20 || echo "Sin permisos para iptables"
    else
        echo "iptables no disponible o sin permisos de root"
    fi
    
    cat << EOF

### Configuración de hosts:
$(cat /etc/hosts 2>/dev/null | grep -v '^#' | head -10)

## 📁 PUNTOS DE MONTAJE Y SISTEMAS DE ARCHIVOS
### Información detallada de montajes:
$(findmnt -D 2>/dev/null | head -15 || mount | head -15)

### Configuración de fstab:
$(cat /etc/fstab 2>/dev/null | grep -v '^#' | grep -v '^)

## 🔄 CONFIGURACIÓN DE ARRANQUE
### Configuración de GRUB:
$(grep -E "^(GRUB_|menuentry)" /etc/default/grub /boot/grub/grub.cfg 2>/dev/null | head -10 || echo "Configuración GRUB no accesible")

### Targets de systemd:
$(systemctl get-default 2>/dev/null)
$(systemctl list-units --type=target --state=active --no-legend 2>/dev/null | head -5)

EOF
}

# 5. Análisis predictivo y recomendaciones
generar_recomendaciones_sistema() {
    local cpu_uso=$(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100-$1}')
    local mem_total=$(free | awk '/Mem:/ {print $2}')
    local mem_usado=$(free | awk '/Mem:/ {print $3}')
    local mem_porcentaje=$(awk "BEGIN {printf \"%.0f\", ($mem_usado/$mem_total)*100}")
    local disco_uso=$(df / | tail -1 | awk '{print $5}' | sed 's/%//')
    local load_avg=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | sed 's/,//')
    local num_cores=$(nproc)
    
    cat << EOF
# ===============================================================================
# ANÁLISIS PREDICTIVO Y RECOMENDACIONES DE OPTIMIZACIÓN
# ===============================================================================

## 📊 MÉTRICAS ACTUALES DEL SISTEMA
CPU en uso: ${cpu_uso}%
Memoria en uso: ${mem_porcentaje}%
Disco raíz en uso: ${disco_uso}%
Carga promedio: ${load_avg} (Núcleos: ${num_cores})

## 🎯 RECOMENDACIONES DE OPTIMIZACIÓN

### 🖥️ Rendimiento de CPU:
EOF

    if (( $(echo "$load_avg > $num_cores * 1.5" | bc -l) )); then
        echo "⚠️  CRÍTICO: Carga del sistema muy alta ($(awk "BEGIN {printf \"%.2f\", $load_avg/$num_cores}") por núcleo)"
        echo "   → Revisar procesos que consumen más CPU"
        echo "   → Considerar aumentar recursos de CPU o optimizar aplicaciones"
    elif (( $(echo "$load_avg > $num_cores" | bc -l) )); then
        echo "🔶 ADVERTENCIA: Carga del sistema elevada"
        echo "   → Monitorear procesos en ejecución"
    else
        echo "✅ Carga del sistema normal"
    fi
    
    echo ""
    echo "### 💾 Gestión de Memoria:"
    
    if [[ $mem_porcentaje -gt 85 ]]; then
        echo "⚠️  CRÍTICO: Uso de memoria muy alto (${mem_porcentaje}%)"
        echo "   → Considerar aumentar RAM o revisar procesos con alta memoria"
        echo "   → Verificar posibles memory leaks en aplicaciones"
    elif [[ $mem_porcentaje -gt 70 ]]; then
        echo "🔶 ADVERTENCIA: Uso de memoria elevado (${mem_porcentaje}%)"
        echo "   → Monitorear consumo de memoria regularmente"
    else
        echo "✅ Uso de memoria normal (${mem_porcentaje}%)"
    fi
    
    # Análisis de SWAP
    local swap_total=$(free | awk '/Swap:/ {print $2}')
    local swap_usado=$(free | awk '/Swap:/ {print $3}')
    
    if [[ $swap_total -gt 0 ]] && [[ $swap_usado -gt 0 ]]; then
        local swap_porcentaje=$(awk "BEGIN {printf \"%.0f\", ($swap_usado/$swap_total)*100}")
        echo "   → Uso de SWAP: ${swap_porcentaje}% - Considerar optimización si es persistente"
    fi
    
    echo ""
    echo "### 🗄️ Almacenamiento:"
    
    if [[ $disco_uso -gt 90 ]]; then
        echo "⚠️  CRÍTICO: Disco raíz casi lleno (${disco_uso}%)"
        echo "   → Limpiar archivos temporales y logs antiguos"
        echo "   → Revisar directorios grandes: du -sh /var/log /tmp /home/*"
    elif [[ $disco_uso -gt 80 ]]; then
        echo "🔶 ADVERTENCIA: Disco raíz con poco espacio (${disco_uso}%)"
        echo "   → Planificar limpieza de archivos"
    else
        echo "✅ Espacio en disco suficiente (${disco_uso}%)"
    fi
    
    cat << EOF

### 🔧 Recomendaciones Generales de Mantenimiento:
# Configurar rotación automática de logs
# Implementar monitoreo continuo de recursos
# Actualizar sistema regularmente con parches de seguridad
# Configurar backups automáticos de configuraciones críticas
# Revisar
