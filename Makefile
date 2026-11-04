all: ests-spec.pdf

ests-spec.pdf: ests-spec.html
	google-chrome --headless --disable-gpu --no-sandbox --no-pdf-header-footer --print-to-pdf="$@" "file://$(CURDIR)/$<"

ests-spec.html: ests-spec.md
	pandoc --from=markdown_mmd -Vcss= -Vpagetitle="[eSTS] Interactive Multi-Factor Authentication" --standalone --to=html ests-spec.md >$@

clean:
	rm ests-spec.pdf ests-spec.html >/dev/null 2>&1 || echo
