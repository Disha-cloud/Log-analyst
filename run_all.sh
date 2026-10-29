#!/usr/bin/env bash
set -e
python -m generator.generate_logs
python -m parser.log_parser
python -m unittest discover -s tests -v
python -m llm.analyzer
python -m validator.claim_validator
python -m validator.evaluate
python -m validator.adversarial_eval
echo "Optional, 10-20 min: python -m llm.ablation"
echo "Demo: streamlit run app.py"