import os

import yara
from pathlib import Path


class YaraScanner:


    def __init__(self, rules_path: str):

        self.rules_path = Path(rules_path)

        self.rules = self._load_rules()


    def _load_rules(self):

        yara_files = list(self.rules_path.rglob("*.yara"))

        if not yara_files:
            raise Exception(f"No YARA rules found in {self.rules_path}")

        rules = {}

        for index, rule in enumerate(yara_files):

            rules[f"rule_{index}"] = str(rule)

        print(f"[YARA] Loaded {len(rules)} rules")

        return yara.compile(filepaths=rules)


    def scan_file(self, file_path: str):

        if not os.path.isfile(file_path):
            return []

        try:
            matches = self.rules.match(filepath=file_path)
        except yara.Error as e:
            print(f"[YARA] Errore su {file_path}: {e}")
            return []

        results = []

        for match in matches:
            results.append({
                "rule": match.rule,
                "tags": match.tags,
                "meta": match.meta
            })

        return results

    
    # Scan di una lista di file, restituendo i risultati in un dizionario
    def scan_files(self, base_path: str, files: list[str]):
        results = []

        for rel_path in files:

            full_path = os.path.join(base_path, rel_path)
            
            if not os.path.isfile(full_path):
                continue

            try:
                results.extend(self.scan_file(full_path))
            except Exception as e:
                print(f"[YARA] Skip {full_path}: {e}")

        return results


    def scan_directory(self, directory: str):

        findings = []


        for file in Path(directory).rglob("*"):

            if not file.is_file():
                continue


            try:

                matches = self.scan_file(
                    str(file)
                )


                if matches:

                    findings.append(
                        {
                            "file": str(file),
                            "matches": matches
                        }
                    )


            except Exception:
                # evita crash su file non leggibili
                pass


        return findings