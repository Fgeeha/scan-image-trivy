.PHONY: scan scan-docker clean
REPORTS_DIR ?= reports

scan:
	./scan_trivy.sh images.txt $(REPORTS_DIR)

scan-docker:
	DOCKERIZED=true ./scan_trivy.sh images.txt $(REPORTS_DIR)

clean:
	rm -rf $(REPORTS_DIR)
