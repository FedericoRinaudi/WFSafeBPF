#ifndef MEASURE_CONFIG_H
#define MEASURE_CONFIG_H

#include "measure_times.h"
#include "measure_bytes.h"

/* Only one experiment can be active at a time, to not interfere with each other */

/* Experimet types */
enum experiment_type {
    EXPERIMENT_TYPE_NONE = 0,
    EXPERIMENT_TYPE_DELAY = 1,
    EXPERIMENT_TYPE_DELAY_CHECKSUM = 2,
    EXPERIMENT_TYPE_DELAY_SEQ_NUM_TRANS = 3,
    EXPERIMENT_TYPE_DELAY_BLAKE2S = 4,
    EXPERIMENT_TYPE_DELAY_MAP_LOOKUP = 5,
    EXPERIMENT_TYPE_DELAY_MAP_UPDATE = 6,
    EXPERIMENT_TYPE_ADDED_BYTES = 7
};


/* Experiment type configuration - if is running an experiment EXPERIMENT_TYPE is passed via -DEXPERIMENT_TYPE flag at compile time, otherwhise no measurments */
#ifndef EXPERIMENT_TYPE
#define EXPERIMENT_TYPE 0
#endif

#if EXPERIMENT_TYPE == EXPERIMENT_TYPE_DELAY
DELAY_MEASURE_DECLARE_REAL(delay_ingress, 1 << 20)
DELAY_MEASURE_DECLARE_REAL(delay_egress, 1 << 20)
#else
DELAY_MEASURE_DECLARE_PLACEHOLDER(delay_ingress, 1 << 20)
DELAY_MEASURE_DECLARE_PLACEHOLDER(delay_egress, 1 << 20)
#endif

#if EXPERIMENT_TYPE == EXPERIMENT_TYPE_DELAY_CHECKSUM
DELAY_MEASURE_DECLARE_REAL(checksum_delay_ingress, 1 << 20)
DELAY_MEASURE_DECLARE_REAL(checksum_delay_egress, 1 << 20)
#else
DELAY_MEASURE_DECLARE_PLACEHOLDER(checksum_delay_ingress, 1 << 20)
DELAY_MEASURE_DECLARE_PLACEHOLDER(checksum_delay_egress, 1 << 20)
#endif  

#if EXPERIMENT_TYPE == EXPERIMENT_TYPE_DELAY_SEQ_NUM_TRANS
DELAY_MEASURE_DECLARE_REAL(seq_num_trans_delay_ingress, 1 << 20)
DELAY_MEASURE_DECLARE_REAL(seq_num_trans_delay_egress, 1 << 20)
#else
DELAY_MEASURE_DECLARE_PLACEHOLDER(seq_num_trans_delay_ingress, 1 << 20)
DELAY_MEASURE_DECLARE_PLACEHOLDER(seq_num_trans_delay_egress, 1 << 20)
#endif

#if EXPERIMENT_TYPE == EXPERIMENT_TYPE_DELAY_BLAKE2S
DELAY_MEASURE_DECLARE_REAL(blake2s_delay, 1 << 20)
#else
DELAY_MEASURE_DECLARE_PLACEHOLDER(blake2s_delay, 1 << 20)
#endif

#if EXPERIMENT_TYPE == EXPERIMENT_TYPE_DELAY_MAP_LOOKUP
DELAY_MEASURE_DECLARE_REAL(map_lookup_delay, 1 << 20)
#else
DELAY_MEASURE_DECLARE_PLACEHOLDER(map_lookup_delay, 1 << 20)
#endif

#if EXPERIMENT_TYPE == EXPERIMENT_TYPE_DELAY_MAP_UPDATE
DELAY_MEASURE_DECLARE_REAL(map_update_delay, 1 << 20)
#else
DELAY_MEASURE_DECLARE_PLACEHOLDER(map_update_delay, 1 << 20)
#endif

#if EXPERIMENT_TYPE == EXPERIMENT_TYPE_ADDED_BYTES
BYTES_MEASURE_DECLARE_REAL(dummy_added_bytes, 1 << 20)
BYTES_MEASURE_DECLARE_REAL(padding_added_bytes, 1 << 20)
BYTES_MEASURE_DECLARE_REAL(fragmentation_added_bytes, 1 << 20)
#else
BYTES_MEASURE_DECLARE_PLACEHOLDER(dummy_added_bytes, 1 << 20)
BYTES_MEASURE_DECLARE_PLACEHOLDER(padding_added_bytes, 1 << 20)
BYTES_MEASURE_DECLARE_PLACEHOLDER(fragmentation_added_bytes, 1 << 20)
#endif

#endif