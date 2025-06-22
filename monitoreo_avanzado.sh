#!/bin/bash
# ===============================================================================
# Script: monitoreo_avanzado.sh
# Autor: Sistema de Monitoreo Inteligente
# Versión: 2.0
# Descripción: Monitor avanzado del sistema con análisis predictivo y alertas
# Compatibilidad: Linux (Ubuntu/Debian/CentOS/RHEL)
# Dependencias: bc, curl, smartctl (smartmontools), sensors (lm-sensors)
# ===============================================================================

# ===============================================================================
# CONFIGURACIÓN GLOBAL Y CONSTANTES
# ===============================================================================

# Colores para interfaz mejorada
readonly ROJO='\033[0;31m'
readonly VERDE='\033[0;32m'
readonly AMARILLO='\033[1;33m'
readonly AZUL='\033[0;34m'
readonly MAGENTA='\033[0;35m'
readonly CIAN='\033[0;36m'
readonly BLANCO='\033[1;37m'
readonly RESET='\033[0m'

# Configuración de umbrales críticos (ajustables según entorno)
readonly CPU_CRITICO=85
readonly CPU_ALTO=70
readonly RAM_CRITICO=90
readonly RAM_ALTO=75
readonly DISCO_CRITICO=90
readonly DISCO_ALTO=80
readonly TEMP_CRITICO=80
readonly TEMP_ALTO=65

# Archivos de configuración y logs
readonly CONFIG_DIR="/etc/monitor-sistema"
readonly LOG_DIR="/var/log/monitor-sistema"
readonly ALERT_LOG="${LOG_DIR}/alertas.log"
readonly HISTORY_FILE="${LOG_DIR}/historial_metricas.csv"

# ===============================================================================
# FUNCIONES DE UTILIDAD Y CONFIGURACIÓN
# ===============================================================================

# Función para inicializar directorios y dependencias
inicializar_sistema() {
    # Crear directorios si no existen
    [[ ! -d "$CONFIG_DIR" ]] && sudo mkdir -p "$CONFIG_DIR" 2>/dev/null
    [[ ! -d "$LOG_DIR" ]] && sudo mkdir -p "$LOG_DIR" 2>/dev/null
    
    # Verificar dependencias críticas
    local dependencias=("bc" "curl" "ps" "free" "df")
    local faltantes=()
    
    for dep in "${dependencias[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            faltantes+=("$dep")
        fi
    done
    
    if [[ ${#faltantes[@]} -gt 0 ]]; then
        echo -e "${ROJO}⚠️  Dependencias faltantes: ${faltantes[*]}${RESET}"
        echo -e "${AMARILLO}💡 Instalar con: sudo apt install ${faltantes[*]} (Ubuntu/Debian)${RESET}"
        return 1
    fi
    
    return 0
}

# Función para logging avanzado con rotación
escribir_log() {
    local nivel="$1"
    local mensaje="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo "[$timestamp] [$nivel] $mensaje" >> "$ALERT_LOG"
    
    # Rotación básica de logs (mantener últimas 1000 líneas)
    if [[ -f "$ALERT_LOG" ]] && [[ $(wc -l < "$ALERT_LOG") -gt 1000 ]]; then
        tail -n 500 "$ALERT_LOG" > "${ALERT_LOG}.tmp" && mv "${ALERT_LOG}.tmp" "$ALERT_LOG"
    fi
}

# Función para envío de alertas (extensible a Slack, email, etc.)
enviar_alerta() {
    local tipo="$1"
    local mensaje="$2"
    local urgencia="$3"
    
    escribir_log "$urgencia" "$tipo: $mensaje"
    
    # Placeholder para integración con sistemas de alertas
    # Webhook de Slack, email, PagerDuty, etc.
    # curl -X POST -H 'Content-type: application/json' \
    #      --data "{\"text\":\"🚨 $tipo: $mensaje\"}" \
    #      "$SLACK_WEBHOOK_URL"
}

# ===============================================================================
# FUNCIONES DE MONITOREO CORE
# ===============================================================================

# Análisis inteligente de CPU con detección de patrones
analizar_cpu() {
    local cpu_idle=$(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print $1}')
    local cpu_uso=$(awk "BEGIN {printf \"%.1f\", 100-$cpu_idle}")
    
    # Obtener información detallada de CPU
    local cpu_cores=$(nproc)
    local cpu_freq=$(cat /proc/cpuinfo | grep "cpu MHz" | head -1 | awk '{print $4}' | cut -d. -f1)
    local load_avg=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | sed 's/,//')
    
    # Análisis de carga vs núcleos
    local carga_relativa=$(awk "BEGIN {printf \"%.2f\", $load_avg/$cpu_cores}")
    
    echo "$cpu_uso|$cpu_cores|$cpu_freq|$load_avg|$carga_relativa"
}

# Monitoreo avanzado de memoria con análisis de fragmentación
analizar_memoria() {
    local mem_info=$(free -m | awk '/Mem:/ {print $2,$3,$4,$6,$7}')
    local total=$(echo $mem_info | awk '{print $1}')
    local usado=$(echo $mem_info | awk '{print $2}')
    local libre=$(echo $mem_info | awk '{print $3}')
    local cache=$(echo $mem_info | awk '{print $4}')
    local disponible=$(echo $mem_info | awk '{print $5}')
    
    local porcentaje_uso=$(awk "BEGIN {printf \"%.1f\", ($usado/$total)*100}")
    local porcentaje_disponible=$(awk "BEGIN {printf \"%.1f\", ($disponible/$total)*100}")
    
    # Análisis de SWAP
    local swap_info=$(free -m | awk '/Swap:/ {print $2,$3}')
    local swap_total=$(echo $swap_info | awk '{print $1}')
    local swap_usado=$(echo $swap_info | awk '{print $2}')
    local swap_porcentaje=0
    
    if [[ $swap_total -gt 0 ]]; then
        swap_porcentaje=$(awk "BEGIN {printf \"%.1f\", ($swap_usado/$swap_total)*100}")
    fi
    
    echo "$total|$usado|$libre|$cache|$disponible|$porcentaje_uso|$porcentaje_disponible|$swap_total|$swap_usado|$swap_porcentaje"
}

# Análisis predictivo de almacenamiento con detección de crecimiento
analizar_almacenamiento() {
    local discos_info=""
    local alerta_espacio=""
    
    while IFS= read -r linea; do
        if [[ $linea =~ ^/dev/ ]]; then
            local dispositivo=$(echo $linea | awk '{print $1}')
            local tamaño=$(echo $linea | awk '{print $2}')
            local usado=$(echo $linea | awk '{print $3}')
            local disponible=$(echo $linea | awk '{print $4}')
            local porcentaje=$(echo $linea | awk '{print $5}' | sed 's/%//')
            local punto_montaje=$(echo $linea | awk '{print $6}')
            
            # Análisis de tendencia (simplificado)
            local estado="NORMAL"
            if [[ $porcentaje -ge $DISCO_CRITICO ]]; then
                estado="CRÍTICO"
                alerta_espacio="$alerta_espacio$dispositivo:$porcentaje% "
            elif [[ $porcentaje -ge $DISCO_ALTO ]]; then
                estado="ALTO"
            fi
            
            discos_info="$discos_info$dispositivo|$tamaño|$usado|$disponible|$porcentaje|$punto_montaje|$estado;"
        fi
    done < <(df -h 2>/dev/null | grep -E '^/dev/')
    
    echo "$discos_info|$alerta_espacio"
}

# Monitoreo de temperatura del sistema
analizar_temperatura() {
    local temp_info="NO_DISPONIBLE"
    local temp_max=0
    
    # Intentar obtener temperatura de sensores
    if command -v sensors &> /dev/null; then
        local temp_output=$(sensors 2>/dev/null | grep -E "Core|temp" | grep -E "[0-9]+\.[0-9]+°C")
        if [[ -n "$temp_output" ]]; then
            temp_max=$(echo "$temp_output" | grep -oE '[0-9]+\.[0-9]+' | sort -n | tail -1)
            temp_info="$temp_max°C"
        fi
    fi
    
    # Fallback: temperatura de zona térmica
    if [[ "$temp_info" == "NO_DISPONIBLE" ]] && [[ -f /sys/class/thermal/thermal_zone0/temp ]]; then
        local temp_miliC=$(cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null)
        if [[ -n "$temp_miliC" ]] && [[ "$temp_miliC" =~ ^[0-9]+$ ]]; then
            temp_max=$(awk "BEGIN {printf \"%.1f\", $temp_miliC/1000}")
            temp_info="$temp_max°C"
        fi
    fi
    
    echo "$temp_info|$temp_max"
}

# Análisis de red y conectividad
analizar_red() {
    local interfaces_info=""
    local conexiones_activas=0
    local latencia_internet="NO_DISPONIBLE"
    
    # Análisis de interfaces de red
    while IFS= read -r linea; do
        local iface=$(echo $linea | awk '{print $2}')
        if [[ "$iface" != "lo" ]]; then
            local ip=$(ip -4 addr show $iface 2>/dev/null | grep -oE 'inet [0-9.]+' | awk '{print $2}')
            local estado=$(cat /sys/class/net/$iface/operstate 2>/dev/null || echo "unknown")
            local rx_bytes=$(cat /sys/class/net/$iface/statistics/rx_bytes 2>/dev/null || echo "0")
            local tx_bytes=$(cat /sys/class/net/$iface/statistics/tx_bytes 2>/dev/null || echo "0")
            
            # Convertir bytes a MB para legibilidad
            local rx_mb=$(awk "BEGIN {printf \"%.2f\", $rx_bytes/1024/1024}")
            local tx_mb=$(awk "BEGIN {printf \"%.2f\", $tx_bytes/1024/1024}")
            
            interfaces_info="$interfaces_info$iface|$ip|$estado|$rx_mb|$tx_mb;"
        fi
    done < <(ip -o link show 2>/dev/null)
    
    # Contar conexiones activas
    conexiones_activas=$(ss -tuln 2>/dev/null | grep -c LISTEN || echo "0")
    
    # Test de latencia a Internet
    if command -v ping &> /dev/null; then
        latencia_internet=$(ping -c 1 -W 2 8.8.8.8 2>/dev/null | grep 'time=' | awk -F'time=' '{print $2}' | awk '{print $1}' || echo "NO_DISPONIBLE")
    fi
    
    echo "$interfaces_info|$conexiones_activas|$latencia_internet"
}

# ===============================================================================
# NUEVAS FUNCIONES AVANZADAS
# ===============================================================================

# 1. Análisis de procesos zombie y huérfanos
analizar_procesos_problematicos() {
    local zombies=$(ps aux | awk '$8 ~ /^Z/ { count++ } END { print count+0 }')
    local procesos_alto_cpu=$(ps -eo pid,comm,%cpu --sort=-%cpu --no-headers | head -5)
    local procesos_alta_memoria=$(ps -eo pid,comm,%mem --sort=-%mem --no-headers | head -5)
    local procesos_totales=$(ps aux --no-headers | wc -l)
    
    # Detectar procesos con tiempo de CPU excesivo
    local procesos_tiempo_excesivo=$(ps -eo pid,comm,time --sort=-time --no-headers | head -3)
    
    echo "$zombies|$procesos_totales|$procesos_alto_cpu|$procesos_alta_memoria|$procesos_tiempo_excesivo"
}

# 2. Monitoreo de servicios críticos del sistema
monitorear_servicios_criticos() {
    local servicios=("ssh" "cron" "rsyslog" "networkd" "systemd-resolved")
    local servicios_estado=""
    local servicios_caidos=""
    
    for servicio in "${servicios[@]}"; do
        if systemctl is-active --quiet "$servicio" 2>/dev/null; then
            servicios_estado="$servicios_estado$servicio:ACTIVO;"
        else
            servicios_estado="$servicios_estado$servicio:INACTIVO;"
            servicios_caidos="$servicios_caidos$servicio "
        fi
    done
    
    # Verificar puertos críticos
    local puertos_criticos=("22" "80" "443")
    local puertos_estado=""
    
    for puerto in "${puertos_criticos[@]}"; do
        if ss -tuln | grep -q ":$puerto "; then
            puertos_estado="$puertos_estado$puerto:ABIERTO;"
        else
            puertos_estado="$puertos_estado$puerto:CERRADO;"
        fi
    done
    
    echo "$servicios_estado|$servicios_caidos|$puertos_estado"
}

# 3. Análisis de seguridad básica y detección de anomalías
analizar_seguridad() {
    local intentos_login_fallidos=0
    local conexiones_sospechosas=""
    local archivos_permisos_incorrectos=0
    
    # Analizar logs de autenticación (últimos 100 registros)
    if [[ -f /var/log/auth.log ]]; then
        intentos_login_fallidos=$(tail -100 /var/log/auth.log 2>/dev/null | grep -c "Failed password" || echo "0")
    elif [[ -f /var/log/secure ]]; then
        intentos_login_fallidos=$(tail -100 /var/log/secure 2>/dev/null | grep -c "authentication failure" || echo "0")
    fi
    
    # Detectar conexiones desde IPs externas inusuales
    local conexiones_externas=$(ss -tuln 2>/dev/null | grep -E ":22|:80|:443" | wc -l || echo "0")
    
    # Verificar archivos con permisos 777 en directorios críticos
    local dirs_criticos=("/etc" "/usr/bin" "/usr/sbin")
    for dir in "${dirs_criticos[@]}"; do
        if [[ -d "$dir" ]]; then
            local count=$(find "$dir" -maxdepth 2 -perm 777 -type f 2>/dev/null | wc -l || echo "0")
            archivos_permisos_incorrectos=$((archivos_permisos_incorrectos + count))
        fi
    done
    
    echo "$intentos_login_fallidos|$conexiones_externas|$archivos_permisos_incorrectos"
}

# 4. Predicción de fallos de hardware
predecir_fallos_hardware() {
    local smart_status="NO_DISPONIBLE"
    local smart_errores=0
    local uptime_dias=0
    
    # Análisis SMART de discos (si está disponible)
    if command -v smartctl &> /dev/null; then
        local discos=$(lsblk -dnro NAME | grep -E '^sd[a-z]$|^nvme[0-9]+n[0-9]+$')
        local discos_con_errores=""
        
        for disco in $discos; do
            local smart_info=$(smartctl -H /dev/$disco 2>/dev/null | grep -i "SMART overall-health")
            if [[ "$smart_info" =~ PASSED ]]; then
                smart_status="SALUDABLE"
            elif [[ "$smart_info" =~ FAILED ]]; then
                smart_status="CRÍTICO"
                discos_con_errores="$discos_con_errores$disco "
                smart_errores=$((smart_errores + 1))
            fi
        done
    fi
    
    # Calcular uptime en días
    if [[ -f /proc/uptime ]]; then
        local uptime_segundos=$(awk '{print int($1)}' /proc/uptime)
        uptime_dias=$((uptime_segundos / 86400))
    fi
    
    # Análisis de memoria de errores de hardware
    local errores_memoria=0
    if [[ -f /proc/meminfo ]]; then
        errores_memoria=$(grep -i "HardwareCorrupted" /proc/meminfo 2>/dev/null | awk '{print $2}' || echo "0")
    fi
    
    echo "$smart_status|$smart_errores|$uptime_dias|$errores_memoria"
}

# 5. Optimización automática y recomendaciones
generar_recomendaciones() {
    local recomendaciones=""
    local optimizaciones_aplicables=""
    
    # Analizar uso de swap
    local swap_uso=$(free | awk '/Swap:/ {if ($2 > 0) print ($3/$2)*100; else print 0}')
    if (( $(echo "$swap_uso > 50" | bc -l) )); then
        recomendaciones="$recomendaciones[RAM] Considerar aumentar memoria física;"
    fi
    
    # Analizar fragmentación de disco
    local disco_principal=$(df / | tail -1 | awk '{print $5}' | sed 's/%//')
    if [[ $disco_principal -gt 85 ]]; then
        recomendaciones="$recomendaciones[DISCO] Limpiar archivos temporales y logs;"
        optimizaciones_aplicables="$optimizaciones_aplicables LIMPIEZA_DISCO;"
    fi
    
    # Analizar carga del sistema
    local load_5min=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $2}' | sed 's/,//')
    local num_cores=$(nproc)
    if (( $(echo "$load_5min > $num_cores * 1.5" | bc -l) )); then
        recomendaciones="$recomendaciones[CPU] Sistema sobrecargado, revisar procesos;"
    fi
    
    # Verificar servicios innecesarios
    local servicios_activos=$(systemctl list-units --type=service --state=active --no-legend | wc -l)
    if [[ $servicios_activos -gt 50 ]]; then
        recomendaciones="$recomendaciones[SERVICIOS] Revisar servicios activos innecesarios;"
    fi
    
    echo "$recomendaciones|$optimizaciones_aplicables"
}

# ===============================================================================
# FUNCIÓN PRINCIPAL DE VISUALIZACIÓN
# ===============================================================================

mostrar_dashboard() {
    clear
    
    # Header con información del sistema
    echo -e "${CIAN}╔══════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${CIAN}║${BLANCO}           🚀 MONITOR SISTEMA AVANZADO v2.0                  ${CIAN}║${RESET}"
    echo -e "${CIAN}║${BLANCO}           $(date '+%A, %d de %B de %Y - %H:%M:%S')           ${CIAN}║${RESET}"
    echo -e "${CIAN}║${BLANCO}           Host: $(hostname) | Kernel: $(uname -r | cut -d- -f1)   ${CIAN}║${RESET}"
    echo -e "${CIAN}╚══════════════════════════════════════════════════════════════╝${RESET}"
    
    # Obtener todas las métricas
    local cpu_data=$(analizar_cpu)
    local mem_data=$(analizar_memoria)
    local disk_data=$(analizar_almacenamiento)
    local temp_data=$(analizar_temperatura)
    local net_data=$(analizar_red)
    local proc_data=$(analizar_procesos_problematicos)
    local serv_data=$(monitorear_servicios_criticos)
    local sec_data=$(analizar_seguridad)
    local hw_data=$(predecir_fallos_hardware)
    local rec_data=$(generar_recomendaciones)
    
    # Parsear datos de CPU
    local cpu_uso=$(echo $cpu_data | cut -d'|' -f1)
    local cpu_cores=$(echo $cpu_data | cut -d'|' -f2)
    local cpu_freq=$(echo $cpu_data | cut -d'|' -f3)
    local load_avg=$(echo $cpu_data | cut -d'|' -f4)
    
    # Parsear datos de memoria
    local mem_total=$(echo $mem_data | cut -d'|' -f1)
    local mem_usado=$(echo $mem_data | cut -d'|' -f2)
    local mem_porcentaje=$(echo $mem_data | cut -d'|' -f6)
    local swap_porcentaje=$(echo $mem_data | cut -d'|' -f10)
    
    # Parsear temperatura
    local temp_info=$(echo $temp_data | cut -d'|' -f1)
    local temp_valor=$(echo $temp_data | cut -d'|' -f2)
    
    # Determinar estado del sistema
    local estado_color=$VERDE
    local estado_texto="ÓPTIMO"
    
    if (( $(echo "$cpu_uso > $CPU_CRITICO" | bc -l) )) || (( $(echo "$mem_porcentaje > $RAM_CRITICO" | bc -l) )) || (( $(echo "$temp_valor > $TEMP_CRITICO" | bc -l) )); then
        estado_color=$ROJO
        estado_texto="CRÍTICO"
        enviar_alerta "SISTEMA" "Estado crítico detectado" "CRITICO"
    elif (( $(echo "$cpu_uso > $CPU_ALTO" | bc -l) )) || (( $(echo "$mem_porcentaje > $RAM_ALTO" | bc -l) )) || (( $(echo "$temp_valor > $TEMP_ALTO" | bc -l) )); then
        estado_color=$AMARILLO
        estado_texto="ALTO"
    fi
    
    # Dashboard principal
    echo -e "\n${AZUL}📊 MÉTRICAS PRINCIPALES${RESET}"
    echo -e "${AZUL}────────────────────────${RESET}"
    
    # Barra de progreso para CPU
    local cpu_barra=$(crear_barra_progreso $cpu_uso 100)
    echo -e "${BLANCO}🖥️  CPU:${RESET} ${cpu_barra} ${cpu_uso}% (${cpu_cores} cores, ${cpu_freq}MHz)"
    
    # Barra de progreso para RAM
    local ram_barra=$(crear_barra_progreso $mem_porcentaje 100)
    echo -e "${BLANCO}💾 RAM:${RESET} ${ram_barra} ${mem_usado}MB/${mem_total}MB (${mem_porcentaje}%)"
    
    # Información de temperatura
    if [[ "$temp_info" != "NO_DISPONIBLE" ]]; then
        echo -e "${BLANCO}🌡️  TEMP:${RESET} $temp_info"
    fi
    
    # Estado general del sistema
    echo -e "\n${MAGENTA}📈 ESTADO DEL SISTEMA:${RESET} ${estado_color}$estado_texto${RESET}"
    echo -e "${MAGENTA}⚡ CARGA PROMEDIO:${RESET} $load_avg"
    
    # Información de almacenamiento
    echo -e "\n${AZUL}💽 ALMACENAMIENTO${RESET}"
    echo -e "${AZUL}─────────────────${RESET}"
    
    local discos_info=$(echo $disk_data | cut -d'|' -f1)
    IFS=';' read -ra DISCOS <<< "$discos_info"
    for disco_info in "${DISCOS[@]}"; do
        if [[ -n "$disco_info" ]]; then
            local dispositivo=$(echo $disco_info | cut -d'|' -f1)
            local porcentaje=$(echo $disco_info | cut -d'|' -f5)
            local punto_montaje=$(echo $disco_info | cut -d'|' -f6)
            local estado=$(echo $disco_info | cut -d'|' -f7)
            
            local color_disco=$VERDE
            [[ "$estado" == "ALTO" ]] && color_disco=$AMARILLO
            [[ "$estado" == "CRÍTICO" ]] && color_disco=$ROJO
            
            local disco_barra=$(crear_barra_progreso $porcentaje 100)
            echo -e "${color_disco}$dispositivo${RESET} ${disco_barra} ${porcentaje}% ($punto_montaje)"
        fi
    done
    
    # Top procesos
    echo -e "\n${AZUL}🔍 TOP PROCESOS (CPU)${RESET}"
    echo -e "${AZUL}─────────────────────${RESET}"
    ps -eo pid,comm,%cpu,%mem --sort=-%cpu --no-headers | head -5 | while read linea; do
        echo -e "${BLANCO}$linea${RESET}"
    done
    
    # Información de red básica
    local conexiones=$(echo $net_data | cut -d'|' -f-1 | tr ';' '\n' | head -2)
    echo -e "\n${AZUL}🌐 RED${RESET}"
    echo -e "${AZUL}──────${RESET}"
    echo "$conexiones" | while IFS='|' read -r iface ip estado rx tx; do
        if [[ -n "$iface" ]]; then
            echo -e "${BLANCO}$iface:${RESET} $ip ($estado) ↓${rx}MB ↑${tx}MB"
        fi
    done
    
    # Guardar métricas históricas
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "$timestamp,$cpu_uso,$mem_porcentaje,$temp_valor" >> "$HISTORY_FILE" 2>/dev/null
    
    echo -e "\n${CIAN}⏱️  Actualización cada 5 segundos | Presiona Ctrl+C para salir${RESET}"
}

# Función auxiliar para crear barras de progreso
crear_barra_progreso() {
    local valor=$1
    local maximo=$2
    local ancho=20
    local progreso=$(awk "BEGIN {printf \"%.0f\", ($valor/$maximo)*$ancho}")
    
    local barra="["
    for ((i=1; i<=ancho; i++)); do
        if [[ $i -le $progreso ]]; then
            if [[ $valor -ge 80 ]]; then
                barra="${barra}${ROJO}█${RESET}"
            elif [[ $valor -ge 60 ]]; then
                barra="${barra}${AMARILLO}█${RESET}"
            else
                barra="${barra}${VERDE}█${RESET}"
            fi
        else
            barra="${barra}░"
        fi
    done
    barra="${barra}]"
    
    echo "$barra"
}

# ===============================================================================
# FUNCIÓN PRINCIPAL Y MANEJO DE SEÑALES
# ===============================================================================

# Manejo de señales para salida limpia
cleanup() {
    clear
    echo -e "${VERDE}🏁 Monitor finalizado. ¡Gracias por usar el Sistema de Monitoreo Avanzado!${RESET}"
    exit 0
}

trap cleanup SIGINT SIGTERM

# Función principal
main() {
    echo -e "${CIAN}🚀 Inicializando Monitor Sistema Avanzado v2.0...${RESET}"
    
    # Verificar e inicializar sistema
    if ! inicializar_sistema; then
        echo -e "${ROJO}❌ Error en la inicialización. Verifique dependencias.${RESET}"
        exit 1
    fi
    
    echo -e "${VERDE}✅ Sistema inicializado correctamente${RESET}"
    sleep 2
    
    # Bucle principal de monitoreo
    while true; do
        mostrar_dashboard
        sleep 5
    done
}

# Verificar si el script se ejecuta directamente
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
