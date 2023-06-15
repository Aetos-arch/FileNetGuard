## Quoi

Description : Securinet est un logiciel de vérification d'intégrité de la sécurité conçu pour les serveurs. Il offre une solution robuste pour détecter les altérations non autorisées des fichiers et surveiller le réseau contre les activités suspectes.

Securinet effectue des vérifications régulières des fichiers en utilisant des algorithmes de hachage avancés tels que MD5, SHA-1, ou SHA-256. Il calcule les empreintes digitales des fichiers et les compare avec les valeurs de référence pour détecter toute altération. En cas de modification, Securinet génère des alertes pour informer les administrateurs du serveur.

Le logiciel surveille également le réseau en analysant les flux de données et les communications pour détecter les tentatives d'accès non autorisées, les attaques par déni de service et autres anomalies potentielles. Il utilise des techniques de détection d'intrusion pour identifier les modèles de trafic malveillant et envoie des alertes en temps réel pour une action immédiate.

## Comment

Les fonctionnalités clés de Securinet comprennent :

-   Vérification régulière de l'intégrité des fichiers par le calcul d'empreintes digitales.
-   Surveillance du réseau pour détecter les activités suspectes et les tentatives d'intrusion.
-   Alerte instantanée en cas de modification de fichier ou de menace détectée.
-   Prise en charge d'algorithmes de hachage robustes pour une sécurité renforcée.
-   Intégration facile avec les infrastructures de serveur existantes.

Avec Securinet, vous pouvez renforcer la sécurité de votre serveur en détectant rapidement les altérations des fichiers et en surveillant le réseau en temps réel. Protégez votre infrastructure contre les menaces et gardez le contrôle sur l'intégrité de votre système avec Securinet.# FileNetGuard

## Détails

### Création de la base de donnée

#### Entités :
Supervised_File (path, hash, first_date, second_date)
- path: Texte (Clé primaire)
- hash: Texte
- first_date: Texte
- second_date: Texte

Supervised_Port (port_number, state, is_listening, first_date, second_date)
- port_number: Entier (Clé primaire)
- state: Texte
- is_listening: Boolean
- first_date: Texte
- second_date: Texte

Report (report_id, date, result, description)
- report_id: Entier (Clé primaire)
- date: Texte
- result: Texte
- description: Texte

File_Modification (modification_id, report_id, path, file_modification_date, old_hash, new_hash)
- modification_id: Entier (Clé primaire)
- report_id: Entier (Clé étrangère faisant référence à Report.report_id)
- path: Texte (Clé étrangère faisant référence à Supervised_File.path)
- file_modification_date: Texte
- old_hash: Texte
- new_hash: Texte

Port_Modification (modification_id, report_id, port_number, port_modification_date, old_state, new_state, old_is_listening, new_is_listening)
- modification_id: Entier (Clé primaire)
- report_id: Entier (Clé étrangère faisant référence à Report.report_id)
- port_number: Entier (Clé étrangère faisant référence à Supervised_Port.port_number)
- port_modification_date: Texte
- old_state: Texte
- new_state: Texte
- old_is_listening: Entier
- new_is_listening: Entier

####  Relations :
-   (1) Un rapport peut avoir aucun ou plusieurs fichiers modifiés. Un fichier modifié est lié à un rapport. (**RAPPORT** - **MODIFICATION_FICHIER**)
-   (1) Un rapport peut avoir aucun ou plusieurs ports modifiés. Un port modifié est lié à un rapport. (**RAPPORT** - **MODIFICATION_PORT**)

####  Attributs :
-   **FICHIER** : **id_fichier** (identifiant unique du fichier), chemin (chemin d'accès du fichier), hash (valeur de hachage du fichier), taille (taille du fichier)
-   **PORT** : **id_port** (identifiant unique du port), numero_port (numéro du port), etat (état du port), taille (taille du port)
-   **RAPPORT** : **id_rapport** (identifiant unique du rapport), date (date du rapport), resultat (résultat du rapport), description (description du rapport)
-   **MODIFICATION_FICHIER** : **id_modification** (identifiant unique de la modification), **id_rapport** (identifiant du rapport lié), date_modification_fichier (date de modification du fichier), ancien_hash (ancienne valeur de hachage), nouveau_hash (nouvelle valeur de hachage)
-   **MODIFICATION_PORT** : **id_modification** (identifiant unique de la modification), **id_rapport** (identifiant du rapport lié), date_modification_etat_port (date de modification du port), ancien_etat (ancien état), nouveau_etat (nouveau état)

####  Explication de la BD
FICHIER : Cette table contient les informations sur les fichiers supervisés. Elle a les colonnes "chemin" (chemin d'accès du fichier) et "hash" (valeur de hachage du fichier).

PORT : Cette table représente les ports supervisés. Elle a les colonnes "numero_port" (numéro du port) et "etat" (état du port).

RAPPORT : Cette table stocke les rapports générés. Elle a les colonnes "id_rapport" (identifiant unique du rapport), "date" (date du rapport), "resultat" (résultat du rapport) et "description" (description du rapport).

MODIFICATION_FICHIER : Cette table enregistre les modifications détectées pour les fichiers supervisés. Elle a les colonnes "id_modification" (identifiant unique de la modification), "id_rapport" (identifiant du rapport lié), "chemin" (chemin d'accès du fichier modifié), "date_modification_fichier" (date de modification du fichier), "ancien_hash" (ancienne valeur de hachage) et "nouveau_hash" (nouvelle valeur de hachage).

MODIFICATION_PORT : Cette table stocke les modifications détectées pour les ports supervisés. Elle a les colonnes "id_modification" (identifiant unique de la modification), "id_rapport" (identifiant du rapport lié), "numero_port" (numéro du port modifié), "date_modification_etat_port" (date de modification de l'état du port), "ancien_etat" (ancien état du port) et "nouveau_etat" (nouveau état du port).