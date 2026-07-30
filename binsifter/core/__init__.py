"""BinSifter's scan engine - no GUI imports allowed in this package.

Kept import-clean of binsifter.gui on purpose: this is the half that needs to
run standalone under the future headless CLI (binsifter-scan) and Docker
mode. If something in here ever needs to import PySide6, that's a sign it
belongs in binsifter.gui instead.
"""
