from pywb.manager import migrate
from argparse import ArgumentParser, RawTextHelpFormatter


if __name__ == '__main__':
    parser = ArgumentParser(formatter_class=RawTextHelpFormatter)
    parser.add_argument('-p', default='./', nargs='?')
    args = parser.parse_args()
    m = migrate.MigrateCDX(args.p)
    if m.count_cdx() > 0:
        m.convert_to_cdxj()
    else:
        print('no cdx files present')
