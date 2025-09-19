.PHONY: scan scan-docker clean scan-latest scan-docker-latest
REPORTS_DIR ?= reports

scan:
	./scan_trivy.sh images.txt $(REPORTS_DIR)

scan-docker:
	DOCKERIZED=true ./scan_trivy.sh images.txt $(REPORTS_DIR)

clean:
	rm -rf $(REPORTS_DIR)

scan-latest:
	./scan_trivy_latest.sh images.txt $(REPORTS_DIR)

scan-docker-latest:
	DOCKERIZED=true ./scan_trivy_latest.sh images.txt $(REPORTS_DIR)