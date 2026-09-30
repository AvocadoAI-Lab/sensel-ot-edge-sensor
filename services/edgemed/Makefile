.PHONY: sample train score train-lstm score-lstm manifest preprocess prepare-ciciomt classifiers anomaly-compare test serve clean-generated

sample:
	python3 scripts/generate_sample.py

train: sample
	python3 scripts/train.py --csv data/sample_flows.csv --label-column label

score: train
	python3 scripts/score.py --csv data/sample_flows.csv --limit 20

train-lstm: sample
	python3 scripts/train_lstm.py --csv data/sample_flows.csv --label-column label

score-lstm: train-lstm
	python3 scripts/score_lstm.py --csv data/sample_flows.csv --limit 20

manifest: sample
	python3 scripts/build_manifest.py --csv data/sample_flows.csv --strategy device_holdout

preprocess: manifest
	python3 scripts/fit_preprocessor.py --csv data/sample_flows.csv --manifest artifacts/manifests/dataset_manifest.json

prepare-ciciomt:
	python3 scripts/prepare_ciciomt.py --root "D:/實習/資料集"

classifiers: prepare-ciciomt
	python3 scripts/train_classifiers.py --dataset-root "D:/實習/資料集"

anomaly-compare: sample
	python3 scripts/evaluate_anomaly_baselines.py --csv data/sample_flows.csv

test:
	python3 -m unittest discover -s tests -v

serve:
	uvicorn app.main:app --host 127.0.0.1 --port 8000

clean-generated:
	rm -f data/sample_flows.csv artifacts/detector.joblib artifacts/training_report.json \
		artifacts/lstm_ae.joblib artifacts/lstm_training_report.json \
		artifacts/preprocessor.joblib artifacts/preprocess_report.json \
		artifacts/dataset_inventory.json artifacts/dataset_provenance.json
	rm -rf artifacts/manifests artifacts/ciciomt artifacts/classifiers
