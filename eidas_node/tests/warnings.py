from warnings import filterwarnings, simplefilter


def setup_warnings_filter():
    # Turn warnings into errors by default
    simplefilter('error')

    # Ignore until django-app-settings is upgraded to >= 0.6
    filterwarnings('ignore', 'NestedSetting is deprecated', DeprecationWarning)
