PYTHON= vp/bin/python
PIP= vp/bin/pip

requirements: requirements.txt vp
	$(PIP) install -r requirements.txt

vp:
	virtualenv -p /usr/bin/python2.7 vp

setup:
	make requirements
	make vp

aws: setup
	$(PYTHON) aws_s3.py $(ARGS) &
