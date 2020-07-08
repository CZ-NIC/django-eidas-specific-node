from warnings import simplefilter


def setup_warnings_filter():
    # Turn warnings into errors by default
    simplefilter('error')
