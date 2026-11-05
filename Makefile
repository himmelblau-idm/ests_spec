.DEFAULT_GOAL := all
.DELETE_ON_ERROR:

PYTHON ?= python3
PANDOC ?= pandoc
# Leave empty to detect Chrome or Chromium at build time.
CHROME ?=
MMDC ?= mmdc

FIGURE_NAMES := fig-01-overview fig-02-common-prefix fig-03-path-selection \
	fig-04-remote-ngc fig-05-password-branch fig-06-tap \
	fig-07-fido-passwordless fig-08-sas-notification fig-09-sas-otp \
	fig-10-sas-sms fig-11-sas-voice fig-12-fido-from-tfa \
	fig-13-interrupts fig-14-kmsi fig-15-proofup fig-16-sspr \
	fig-17-autosubmit fig-18-consumers-federated fig-19-device-code \
	fig-20-v1-v2 fig-21-token-lineage fig-22-cookies fig-23-errors \
	fig-24-authz-response
FIGURE_SOURCES := $(addprefix figures/src/,$(addsuffix .mmd,$(FIGURE_NAMES)))
FIGURE_IMAGES := $(patsubst figures/src/%.mmd,images/%.png,$(FIGURE_SOURCES))

.PHONY: all figures clean

all: ests-spec.pdf

figures: $(FIGURE_IMAGES)

# GNU Make 4.3 grouped targets: generate the sources once, even with make -j.
$(FIGURE_SOURCES) &: figures/mkfigs.py
	$(PYTHON) figures/mkfigs.py

images/%.png: figures/src/%.mmd figures/build.sh figures/browser.sh figures/mermaid-config.json figures/puppeteer.json
	CHROME="$(CHROME)" MMDC="$(MMDC)" sh figures/build.sh "$<" "$@"

ests-spec.pdf: ests-spec.html figures/browser.sh
	@browser=$$(sh figures/browser.sh "$(CHROME)") && \
		"$$browser" --headless --disable-gpu --no-sandbox --no-pdf-header-footer --print-to-pdf="$@" "file://$(CURDIR)/$<"

ests-spec.html: ests-spec.md $(FIGURE_IMAGES)
	$(PANDOC) --from=markdown_mmd -Vcss= -Vpagetitle="[eSTS] Interactive Multi-Factor Authentication" --standalone --to=html ests-spec.md >$@

clean:
	rm -f ests-spec.pdf ests-spec.html $(FIGURE_IMAGES)
