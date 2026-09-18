#!/bin/bash
# Executado para gravação (asciinema/VHS): encerra sozinho após ~14s
# para não depender de tecla 'q'. Uso: asciinema rec -c ./demo-run.sh demo.cast
./target/release/pingenty dashboard --interface wlp0s20f3 --ping-hosts "1.1.1.1,8.8.8.8" --dns-domains "cloudflare.com,github.com" & PINGENTY_PID=$!
sleep 14
kill -TERM "$PINGENTY_PID" 2>/dev/null
wait "$PINGENTY_PID" 2>/dev/null
