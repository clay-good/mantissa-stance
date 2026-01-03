# stance.dspm.cost

DSPM Cost Analysis module.

Provides capabilities for analyzing cloud storage costs and identifying
cold data that can be archived or deleted to save costs.

Features:
- Cold data detection (objects not accessed in X days)
- Storage cost estimation per bucket/container
- Archive candidate identification (Glacier, Nearline, Cool tier)
- Delete candidate identification (old unused data)
