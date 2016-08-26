from pywb.manager import migrate

if __name__ == '__main__':
    m = migrate.MigrateCDX('/home/john/my-fork-wail/archiveIndexes/')
    print(m.convert_to_cdxj())