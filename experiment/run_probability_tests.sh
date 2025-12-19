#!/bin/bash

# Script per testare diverse combinazioni di probabilità
# Testa tutte le combinazioni di padding, dummy e fragmentation fino al 50%

set -e

# Percorsi
CLIENT_PATH="/home/ubuntu/WFSafeBPF/client/target/release/client"
EXPERIMENT_PATH="/home/ubuntu/WFSafeBPF/experiment/client"
RESULTS_DIR="/home/ubuntu/WFSafeBPF/results"

# Crea directory risultati se non esiste
mkdir -p "$RESULTS_DIR"

# Timestamp per questa sessione di test
SESSION_TIMESTAMP=$(date +%Y%m%d_%H%M%S)
SESSION_DIR="$RESULTS_DIR/session_$SESSION_TIMESTAMP"
mkdir -p "$SESSION_DIR"

echo "==================================="
echo "Test Probabilità - Sessione: $SESSION_TIMESTAMP"
echo "==================================="
echo ""

# Probabilità da testare (0%, 10%, 20%, 30%, 40%, 50%)
PROBABILITIES=(0 10 20 30 50 70 100)

# Contatore test
TEST_NUM=0
TOTAL_TESTS=$((${#PROBABILITIES[@]} * ${#PROBABILITIES[@]} * ${#PROBABILITIES[@]}))

echo "Totale combinazioni da testare: $TOTAL_TESTS"
echo ""

# Funzione per aggiornare una probabilità
update_probability() {
    local field=$1
    local value=$2
    echo "  → Impostando $field a $value%..."
    sudo "$CLIENT_PATH" update server1 "$field" "$value" > /dev/null 2>&1
    sleep 1  # Attesa per applicazione configurazione
}

# Funzione per eseguire un test
run_test() {
    local frag=$1
    local dummy=$2
    local padding=$3
    
    TEST_NUM=$((TEST_NUM + 1))
    
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Test $TEST_NUM/$TOTAL_TESTS"
    echo "Padding: ${padding}% | Dummy: ${dummy}% | Fragmentation: ${frag}%"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    # Aggiorna le probabilità
    update_probability "padding_probability" "$padding"
    update_probability "dummy_probability" "$dummy"
    update_probability "fragmentation_probability" "$frag"
    
    # Nome file risultati (CSV per analisi)
    RESULT_FILE="$SESSION_DIR/results_p${padding}_d${dummy}_f${frag}.csv"
    
    echo "  → Avvio esperimento..."
    echo "  → Output salvato in: $RESULT_FILE"
    
    # Esegui il client degli esperimenti (usa binario pre-compilato)
    EXPERIMENT_BIN="$EXPERIMENT_PATH/target/release/experiment-client"
    
    # Timeout di 1200 secondi per ogni test
    if timeout 1200 "$EXPERIMENT_BIN" "$RESULT_FILE" 2>&1; then
        echo "  ✓ Test completato con successo"
    else
        EXIT_CODE=$?
        if [ $EXIT_CODE -eq 124 ]; then
            echo "  ⚠ Test timeout dopo 1200 secondi"
        else
            echo "  ✗ Test fallito con exit code: $EXIT_CODE"
        fi
    fi
    
    # Pausa tra i test
    sleep 3
}

# Loop su tutte le combinazioni
for frag in "${PROBABILITIES[@]}"; do
    for dummy in "${PROBABILITIES[@]}"; do
        for padding in "${PROBABILITIES[@]}"; do
            run_test "$frag" "$dummy" "$padding"
        done
    done
done

echo ""
echo "==================================="
echo "Tutti i test completati!"
echo "==================================="
echo "Risultati salvati in: $SESSION_DIR"
echo ""

# Genera un report sommario con statistiche RTT
SUMMARY_FILE="$SESSION_DIR/summary.csv"
echo "# Experiment Summary - Session $SESSION_TIMESTAMP" > "$SUMMARY_FILE"
echo "padding_prob,dummy_prob,frag_prob,avg_rtt_us,min_rtt_us,max_rtt_us,status" >> "$SUMMARY_FILE"

for result_file in "$SESSION_DIR"/results_*.csv; do
    if [ -f "$result_file" ]; then
        filename=$(basename "$result_file")
        # Estrai probabilità dal nome file: results_pXX_dYY_fZZ.csv
        padding=$(echo "$filename" | sed -n 's/results_p\([0-9]*\)_d[0-9]*_f[0-9]*.csv/\1/p')
        dummy=$(echo "$filename" | sed -n 's/results_p[0-9]*_d\([0-9]*\)_f[0-9]*.csv/\1/p')
        frag=$(echo "$filename" | sed -n 's/results_p[0-9]*_d[0-9]*_f\([0-9]*\).csv/\1/p')
        
        # Estrai statistiche dal file
        if grep -q "avg_rtt_us" "$result_file" 2>/dev/null; then
            avg=$(grep "avg_rtt_us" "$result_file" | cut -d',' -f2)
            min=$(grep "min_rtt_us" "$result_file" | cut -d',' -f2)
            max=$(grep "max_rtt_us" "$result_file" | cut -d',' -f2)
            status="success"
        else
            avg="N/A"
            min="N/A"
            max="N/A"
            status="failed"
        fi
        
        echo "$padding,$dummy,$frag,$avg,$min,$max,$status" >> "$SUMMARY_FILE"
    fi
done

echo ""
echo "Summary salvato in: $SUMMARY_FILE"
echo ""
echo "Anteprima risultati:"
column -t -s',' "$SUMMARY_FILE" | head -20
