# Fallback to rebar on PATH
REBAR3 ?= $(shell which rebar3)

REBAR3_URL = "https://s3.amazonaws.com/rebar3/rebar3"

# And finally, prep to download rebar if all else fails
ifeq ($(REBAR3),)
REBAR3 = $(CURDIR)/rebar3
endif

all: $(REBAR3)
	@$(REBAR3) do clean, compile, eunit, dialyzer

rel: all
	@$(REBAR3) release

test: $(REBAR3)
	@$(REBAR3) eunit

dialyzer:
	@$(REBAR3) dialyzer

$(REBAR3):
	curl -Lo rebar3 $(REBAR3_URL) || wget $(REBAR3_URL)
	chmod a+x rebar3

update:
	$(REBAR3) update

clean:
	$(REBAR3) clean

distclean: clean
	@rm -rf _build

doc:
	@rebar doc skip_deps=true

.PHONY: doc test
