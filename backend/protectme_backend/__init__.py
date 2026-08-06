import pymysql

# PyMySQL est un driver MySQL 100% Python : contrairement a mysqlclient, il
# ne necessite aucune compilation ni bibliotheque systeme (libmysqlclient-dev),
# donc beaucoup plus simple a installer sur n'importe quel poste (Windows
# inclus). On le fait passer pour MySQLdb, l'API que Django attend.
pymysql.install_as_MySQLdb()
