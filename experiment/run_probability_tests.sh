#!/bin/bash

# Script per testare diverse combinazioni di probabilità
# Testa tutte le combinazioni di padding, dummy e fragmentation fino al 50%

set -e

# Percorsi
CLIENT_PATH="/home/ubuntu/WFSafeBPF/client/target/release/client"
QUERY_CLIENT_BIN="/home/ubuntu/WFSafeBPF/experiment/client/target/release/query-client"
RESOLUTION_CLIENT_BIN="/home/ubuntu/WFSafeBPF/experiment/client/target/release/resolution-client"
RESULTS_DIR="/home/ubuntu/WFSafeBPF/results"

# Crea directory risultati se non esiste
mkdir -p "$RESULTS_DIR"

# Timestamp per questa sessione di test
SESSION_TIMESTAMP=$(date +%Y%m%d_%H%M%S)
SESSION_DIR="$RESULTS_DIR/session_$SESSION_TIMESTAMP"
QUERY_DIR="$SESSION_DIR/query"
RESOLUTION_DIR="$SESSION_DIR/resolution"
mkdir -p "$SESSION_DIR"
mkdir -p "$QUERY_DIR" "$RESOLUTION_DIR"

echo "==================================="
echo "Test Probabilità - Sessione: $SESSION_TIMESTAMP"
echo "==================================="
echo ""

# Probabilità da testare
PROBABILITIES=(0 10 20 30 50 70 100)

# Numero di round: ogni round esegue tutte le combinazioni in ordine random.
# Aumenta ROUNDS se vuoi interleaving (es. 30 round con 100 misure per run).
ROUNDS=30

# Prepara lista combinazioni
COMBOS=()
for frag in "${PROBABILITIES[@]}"; do
    for dummy in "${PROBABILITIES[@]}"; do
        for padding in "${PROBABILITIES[@]}"; do
            COMBOS+=("${padding},${dummy},${frag}")
        done
    done
done

# Contatore test
TEST_NUM=0
TOTAL_TESTS=$((${#COMBOS[@]} * ROUNDS))

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
    local round=$4
    
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
    QUERY_FILE="$QUERY_DIR/results_p${padding}_d${dummy}_f${frag}_r${round}.csv"
    RESOLUTION_FILE="$RESOLUTION_DIR/results_p${padding}_d${dummy}_f${frag}_r${round}.csv"
    
    echo "  → Avvio esperimento..."
    echo "  → Output query: $QUERY_FILE"
    echo "  → Output resolution: $RESOLUTION_FILE"
    
    # Esegui i client degli esperimenti (usa binari pre-compilati)
    # Timeout di 1200 secondi per ogni test
    if timeout 1200 "$QUERY_CLIENT_BIN" "$QUERY_FILE" 2>&1; then
        echo "  ✓ Query completato con successo"
    else
        EXIT_CODE=$?
        if [ $EXIT_CODE -eq 124 ]; then
            echo "  ⚠ Query timeout dopo 1200 secondi"
        else
            echo "  ✗ Query fallito con exit code: $EXIT_CODE"
        fi
    fi

    if timeout 1200 "$RESOLUTION_CLIENT_BIN" "$RESOLUTION_FILE" 2>&1; then
        echo "  ✓ Resolution completato con successo"
    else
        EXIT_CODE=$?
        if [ $EXIT_CODE -eq 124 ]; then
            echo "  ⚠ Resolution timeout dopo 1200 secondi"
        else
            echo "  ✗ Resolution fallito con exit code: $EXIT_CODE"
        fi
    fi
    
    # Pausa tra i test
    sleep 3
}

# Loop interleaved: ogni round esegue tutte le combinazioni in ordine random
for round in $(seq 1 "$ROUNDS"); do
    echo ""
    echo "===== Round $round/$ROUNDS ====="
    echo ""

    mapfile -t SHUFFLED < <(printf "%s\n" "${COMBOS[@]}" | shuf)
    for combo in "${SHUFFLED[@]}"; do
        IFS=',' read -r padding dummy frag <<< "$combo"
        run_test "$frag" "$dummy" "$padding" "$round"
    done
done

echo ""
echo "==================================="
echo "Tutti i test completati!"
echo "==================================="
echo "Risultati salvati in: $SESSION_DIR"
echo ""

# Genera un report sommario con statistiche RTT
QUERY_SUMMARY="$SESSION_DIR/summary_query.csv"
RESOLUTION_SUMMARY="$SESSION_DIR/summary_resolution.csv"
echo "# Experiment Summary - Session $SESSION_TIMESTAMP (query)" > "$QUERY_SUMMARY"
echo "padding_prob,dummy_prob,frag_prob,avg_rtt_us,min_rtt_us,max_rtt_us,status" >> "$QUERY_SUMMARY"
echo "# Experiment Summary - Session $SESSION_TIMESTAMP (resolution)" > "$RESOLUTION_SUMMARY"
echo "padding_prob,dummy_prob,frag_prob,avg_rtt_us,min_rtt_us,max_rtt_us,status" >> "$RESOLUTION_SUMMARY"

for result_file in "$QUERY_DIR"/results_*.csv; do
    if [ -f "$result_file" ]; then
        filename=$(basename "$result_file")
        # Estrai probabilità dal nome file: results_pXX_dYY_fZZ[_rN].csv
        padding=$(echo "$filename" | sed -n 's/results_p\([0-9]*\)_d[0-9]*_f[0-9]*.*.csv/\1/p')
        dummy=$(echo "$filename" | sed -n 's/results_p[0-9]*_d\([0-9]*\)_f[0-9]*.*.csv/\1/p')
        frag=$(echo "$filename" | sed -n 's/results_p[0-9]*_d[0-9]*_f\([0-9]*\).*\.csv/\1/p')
        
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
        
        echo "$padding,$dummy,$frag,$avg,$min,$max,$status" >> "$QUERY_SUMMARY"
    fi
done

for result_file in "$RESOLUTION_DIR"/results_*.csv; do
    if [ -f "$result_file" ]; then
        filename=$(basename "$result_file")
        # Estrai probabilità dal nome file: results_pXX_dYY_fZZ[_rN].csv
        padding=$(echo "$filename" | sed -n 's/results_p\([0-9]*\)_d[0-9]*_f[0-9]*.*.csv/\1/p')
        dummy=$(echo "$filename" | sed -n 's/results_p[0-9]*_d\([0-9]*\)_f[0-9]*.*.csv/\1/p')
        frag=$(echo "$filename" | sed -n 's/results_p[0-9]*_d[0-9]*_f\([0-9]*\).*\.csv/\1/p')

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

        echo "$padding,$dummy,$frag,$avg,$min,$max,$status" >> "$RESOLUTION_SUMMARY"
    fi
done

echo ""
echo "Summary salvato in: $QUERY_SUMMARY"
echo "Summary salvato in: $RESOLUTION_SUMMARY"
echo ""
echo "Anteprima risultati:"
column -t -s',' "$QUERY_SUMMARY" | head -20
column -t -s',' "$RESOLUTION_SUMMARY" | head -20
