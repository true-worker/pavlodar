# Audited service slice
All data-access routes are declared in operations.ROUTES. Authentication supplies request.user.id before routing. The only database lifecycle operations are in database.py. The in-memory event sink is sufficient for this focused coverage test; durability and cryptographic protection are evaluated separately, not as part of this fixture.
