import sys, os

if getattr(sys, 'frozen', False):
    # we are running in a bundle
    frozen = 'ever so'
    bundle_dir = sys._MEIPASS
    DEFAULT_CONFIG = os.path.join(bundle_dir,'default_config.yaml')
else:
    DEFAULT_CONFIG = 'wbManager/default_config.yaml'

def get_test_dir():
    if getattr(sys, 'frozen', False):
        # we are running in a bundle
        frozen = 'ever so'
        bundle_dir = sys._MEIPASS
        return os.path.join(os.path.dirname(os.path.realpath(bundle_dir)),
                            'sample_archive') + os.path.sep
    else:
        return os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                        'sample_archive') + os.path.sep
