png: \
	ladder_to_msc_test.png \
	$(NULL)

%.png: %.msc
	mscgen -T png -o $@ $<

%.msc: %.ladder
	@which ladder_to_msc.py || (echo 'PLEASE POINT YOUR $$PATH AT libosmocore/contrib/ladder_to_msc.py' && false)
	ladder_to_msc.py -i $< -o $@
