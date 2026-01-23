"""
Design Tokens for Mantissa Stance UI.

This module defines the foundational design constants used throughout
the application. These tokens ensure visual consistency across all
outputs - web dashboard, static reports, and CLI visualizations.

Design tokens are the smallest pieces of a design system: colors,
typography, spacing, shadows, etc. They're platform-agnostic and
can be transformed into CSS, Python constants, or any other format.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Dict


class Colors:
    """
    Color palette for Mantissa Stance.

    Organized by semantic meaning rather than visual appearance.
    This allows consistent usage across light/dark themes.
    """

    # Brand Colors
    BRAND_PRIMARY = "#2563eb"      # Blue 600
    BRAND_PRIMARY_LIGHT = "#3b82f6"  # Blue 500
    BRAND_PRIMARY_DARK = "#1d4ed8"   # Blue 700
    BRAND_SECONDARY = "#1e3a5f"      # Dark blue

    # Severity Colors (WCAG AA compliant)
    SEVERITY_CRITICAL = "#dc2626"    # Red 600
    SEVERITY_CRITICAL_BG = "#fef2f2"  # Red 50
    SEVERITY_CRITICAL_BORDER = "#fecaca"  # Red 200

    SEVERITY_HIGH = "#ea580c"        # Orange 600
    SEVERITY_HIGH_BG = "#fff7ed"     # Orange 50
    SEVERITY_HIGH_BORDER = "#fed7aa"  # Orange 200

    SEVERITY_MEDIUM = "#ca8a04"      # Yellow 600
    SEVERITY_MEDIUM_BG = "#fefce8"   # Yellow 50
    SEVERITY_MEDIUM_BORDER = "#fef08a"  # Yellow 200

    SEVERITY_LOW = "#2563eb"         # Blue 600
    SEVERITY_LOW_BG = "#eff6ff"      # Blue 50
    SEVERITY_LOW_BORDER = "#bfdbfe"   # Blue 200

    SEVERITY_INFO = "#6b7280"        # Gray 500
    SEVERITY_INFO_BG = "#f9fafb"     # Gray 50
    SEVERITY_INFO_BORDER = "#e5e7eb"  # Gray 200

    # Status Colors
    STATUS_OPEN = "#dc2626"          # Red 600
    STATUS_OPEN_BG = "#fef2f2"       # Red 50

    STATUS_RESOLVED = "#16a34a"      # Green 600
    STATUS_RESOLVED_BG = "#f0fdf4"   # Green 50

    STATUS_SUPPRESSED = "#737373"    # Gray 500
    STATUS_SUPPRESSED_BG = "#f5f5f5"  # Gray 100

    STATUS_FALSE_POSITIVE = "#9333ea"  # Purple 600
    STATUS_FALSE_POSITIVE_BG = "#faf5ff"  # Purple 50

    # Semantic Colors
    SUCCESS = "#16a34a"              # Green 600
    SUCCESS_BG = "#f0fdf4"           # Green 50

    WARNING = "#ca8a04"              # Yellow 600
    WARNING_BG = "#fefce8"           # Yellow 50

    ERROR = "#dc2626"                # Red 600
    ERROR_BG = "#fef2f2"             # Red 50

    # Neutral Colors
    TEXT_PRIMARY = "#111827"         # Gray 900
    TEXT_SECONDARY = "#6b7280"       # Gray 500
    TEXT_MUTED = "#9ca3af"           # Gray 400
    TEXT_INVERSE = "#ffffff"         # White

    BG_PRIMARY = "#ffffff"           # White
    BG_SECONDARY = "#f9fafb"         # Gray 50
    BG_TERTIARY = "#f3f4f6"          # Gray 100

    BORDER_DEFAULT = "#e5e7eb"       # Gray 200
    BORDER_LIGHT = "#f3f4f6"         # Gray 100
    BORDER_DARK = "#d1d5db"          # Gray 300

    # Gradient
    HEADER_GRADIENT_START = "#1e3a5f"
    HEADER_GRADIENT_END = "#2563eb"

    @classmethod
    def get_severity_colors(cls, severity: str) -> Dict[str, str]:
        """Get color set for a severity level."""
        severity = severity.lower()
        mapping = {
            "critical": {
                "text": cls.SEVERITY_CRITICAL,
                "bg": cls.SEVERITY_CRITICAL_BG,
                "border": cls.SEVERITY_CRITICAL_BORDER,
            },
            "high": {
                "text": cls.SEVERITY_HIGH,
                "bg": cls.SEVERITY_HIGH_BG,
                "border": cls.SEVERITY_HIGH_BORDER,
            },
            "medium": {
                "text": cls.SEVERITY_MEDIUM,
                "bg": cls.SEVERITY_MEDIUM_BG,
                "border": cls.SEVERITY_MEDIUM_BORDER,
            },
            "low": {
                "text": cls.SEVERITY_LOW,
                "bg": cls.SEVERITY_LOW_BG,
                "border": cls.SEVERITY_LOW_BORDER,
            },
            "info": {
                "text": cls.SEVERITY_INFO,
                "bg": cls.SEVERITY_INFO_BG,
                "border": cls.SEVERITY_INFO_BORDER,
            },
        }
        return mapping.get(severity, mapping["info"])

    @classmethod
    def get_status_colors(cls, status: str) -> Dict[str, str]:
        """Get color set for a status."""
        status = status.lower().replace(" ", "_")
        mapping = {
            "open": {"text": cls.STATUS_OPEN, "bg": cls.STATUS_OPEN_BG},
            "resolved": {"text": cls.STATUS_RESOLVED, "bg": cls.STATUS_RESOLVED_BG},
            "suppressed": {"text": cls.STATUS_SUPPRESSED, "bg": cls.STATUS_SUPPRESSED_BG},
            "false_positive": {"text": cls.STATUS_FALSE_POSITIVE, "bg": cls.STATUS_FALSE_POSITIVE_BG},
        }
        return mapping.get(status, mapping["open"])


class Typography:
    """Typography settings for consistent text styling."""

    # Font Families
    FONT_FAMILY_SANS = "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif"
    FONT_FAMILY_MONO = "ui-monospace, SFMono-Regular, 'SF Mono', Menlo, Consolas, 'Liberation Mono', monospace"

    # Font Sizes (rem based for accessibility)
    FONT_SIZE_XS = "0.75rem"     # 12px
    FONT_SIZE_SM = "0.8125rem"   # 13px
    FONT_SIZE_BASE = "0.875rem"  # 14px
    FONT_SIZE_MD = "1rem"        # 16px
    FONT_SIZE_LG = "1.125rem"    # 18px
    FONT_SIZE_XL = "1.25rem"     # 20px
    FONT_SIZE_2XL = "1.5rem"     # 24px
    FONT_SIZE_3XL = "1.75rem"    # 28px
    FONT_SIZE_4XL = "2.25rem"    # 36px

    # Font Weights
    FONT_WEIGHT_NORMAL = "400"
    FONT_WEIGHT_MEDIUM = "500"
    FONT_WEIGHT_SEMIBOLD = "600"
    FONT_WEIGHT_BOLD = "700"

    # Line Heights
    LINE_HEIGHT_TIGHT = "1.25"
    LINE_HEIGHT_NORMAL = "1.5"
    LINE_HEIGHT_RELAXED = "1.625"

    # Letter Spacing
    LETTER_SPACING_TIGHT = "-0.025em"
    LETTER_SPACING_NORMAL = "0"
    LETTER_SPACING_WIDE = "0.025em"
    LETTER_SPACING_WIDER = "0.05em"


class Spacing:
    """Spacing scale for margins, padding, and gaps."""

    # Base unit: 4px
    SPACE_0 = "0"
    SPACE_1 = "0.25rem"   # 4px
    SPACE_2 = "0.5rem"    # 8px
    SPACE_3 = "0.75rem"   # 12px
    SPACE_4 = "1rem"      # 16px
    SPACE_5 = "1.25rem"   # 20px
    SPACE_6 = "1.5rem"    # 24px
    SPACE_8 = "2rem"      # 32px
    SPACE_10 = "2.5rem"   # 40px
    SPACE_12 = "3rem"     # 48px
    SPACE_16 = "4rem"     # 64px
    SPACE_20 = "5rem"     # 80px

    # Component-specific spacing
    CARD_PADDING = "1.25rem"       # 20px
    SECTION_GAP = "1.5rem"         # 24px
    TABLE_CELL_PADDING = "0.875rem 1rem"  # 14px 16px
    BADGE_PADDING = "0.25rem 0.625rem"    # 4px 10px


class Shadows:
    """Box shadow definitions for depth and elevation."""

    SHADOW_NONE = "none"
    SHADOW_SM = "0 1px 2px 0 rgba(0, 0, 0, 0.05)"
    SHADOW_DEFAULT = "0 1px 3px 0 rgba(0, 0, 0, 0.1), 0 1px 2px -1px rgba(0, 0, 0, 0.1)"
    SHADOW_MD = "0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -2px rgba(0, 0, 0, 0.1)"
    SHADOW_LG = "0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -4px rgba(0, 0, 0, 0.1)"
    SHADOW_XL = "0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 8px 10px -6px rgba(0, 0, 0, 0.1)"

    # Interactive shadows
    SHADOW_HOVER = "0 4px 12px rgba(0, 0, 0, 0.1)"
    SHADOW_FOCUS = "0 0 0 3px rgba(37, 99, 235, 0.2)"


class BorderRadius:
    """Border radius values for rounded corners."""

    RADIUS_NONE = "0"
    RADIUS_SM = "0.25rem"    # 4px
    RADIUS_DEFAULT = "0.375rem"  # 6px
    RADIUS_MD = "0.5rem"     # 8px
    RADIUS_LG = "0.75rem"    # 12px
    RADIUS_XL = "1rem"       # 16px
    RADIUS_2XL = "1.5rem"    # 24px
    RADIUS_FULL = "9999px"   # Pill shape


class Breakpoints:
    """Responsive breakpoints for media queries."""

    SM = "640px"
    MD = "768px"
    LG = "1024px"
    XL = "1280px"
    XXL = "1536px"


class Transitions:
    """Transition timing for animations."""

    DURATION_FAST = "150ms"
    DURATION_DEFAULT = "200ms"
    DURATION_SLOW = "300ms"

    EASING_DEFAULT = "cubic-bezier(0.4, 0, 0.2, 1)"
    EASING_IN = "cubic-bezier(0.4, 0, 1, 1)"
    EASING_OUT = "cubic-bezier(0, 0, 0.2, 1)"
    EASING_IN_OUT = "cubic-bezier(0.4, 0, 0.2, 1)"


def get_css_variables() -> str:
    """
    Generate CSS custom properties from design tokens.

    Returns:
        CSS string with :root variables
    """
    return f"""
:root {{
    /* Brand Colors */
    --color-brand-primary: {Colors.BRAND_PRIMARY};
    --color-brand-primary-light: {Colors.BRAND_PRIMARY_LIGHT};
    --color-brand-primary-dark: {Colors.BRAND_PRIMARY_DARK};
    --color-brand-secondary: {Colors.BRAND_SECONDARY};

    /* Severity Colors */
    --color-critical: {Colors.SEVERITY_CRITICAL};
    --color-critical-bg: {Colors.SEVERITY_CRITICAL_BG};
    --color-critical-border: {Colors.SEVERITY_CRITICAL_BORDER};

    --color-high: {Colors.SEVERITY_HIGH};
    --color-high-bg: {Colors.SEVERITY_HIGH_BG};
    --color-high-border: {Colors.SEVERITY_HIGH_BORDER};

    --color-medium: {Colors.SEVERITY_MEDIUM};
    --color-medium-bg: {Colors.SEVERITY_MEDIUM_BG};
    --color-medium-border: {Colors.SEVERITY_MEDIUM_BORDER};

    --color-low: {Colors.SEVERITY_LOW};
    --color-low-bg: {Colors.SEVERITY_LOW_BG};
    --color-low-border: {Colors.SEVERITY_LOW_BORDER};

    --color-info: {Colors.SEVERITY_INFO};
    --color-info-bg: {Colors.SEVERITY_INFO_BG};
    --color-info-border: {Colors.SEVERITY_INFO_BORDER};

    /* Status Colors */
    --color-status-open: {Colors.STATUS_OPEN};
    --color-status-open-bg: {Colors.STATUS_OPEN_BG};
    --color-status-resolved: {Colors.STATUS_RESOLVED};
    --color-status-resolved-bg: {Colors.STATUS_RESOLVED_BG};
    --color-status-suppressed: {Colors.STATUS_SUPPRESSED};
    --color-status-suppressed-bg: {Colors.STATUS_SUPPRESSED_BG};
    --color-status-false-positive: {Colors.STATUS_FALSE_POSITIVE};
    --color-status-false-positive-bg: {Colors.STATUS_FALSE_POSITIVE_BG};

    /* Semantic Colors */
    --color-success: {Colors.SUCCESS};
    --color-success-bg: {Colors.SUCCESS_BG};
    --color-warning: {Colors.WARNING};
    --color-warning-bg: {Colors.WARNING_BG};
    --color-error: {Colors.ERROR};
    --color-error-bg: {Colors.ERROR_BG};

    /* Text Colors */
    --color-text-primary: {Colors.TEXT_PRIMARY};
    --color-text-secondary: {Colors.TEXT_SECONDARY};
    --color-text-muted: {Colors.TEXT_MUTED};
    --color-text-inverse: {Colors.TEXT_INVERSE};

    /* Background Colors */
    --color-bg-primary: {Colors.BG_PRIMARY};
    --color-bg-secondary: {Colors.BG_SECONDARY};
    --color-bg-tertiary: {Colors.BG_TERTIARY};

    /* Border Colors */
    --color-border-default: {Colors.BORDER_DEFAULT};
    --color-border-light: {Colors.BORDER_LIGHT};
    --color-border-dark: {Colors.BORDER_DARK};

    /* Typography */
    --font-family-sans: {Typography.FONT_FAMILY_SANS};
    --font-family-mono: {Typography.FONT_FAMILY_MONO};

    --font-size-xs: {Typography.FONT_SIZE_XS};
    --font-size-sm: {Typography.FONT_SIZE_SM};
    --font-size-base: {Typography.FONT_SIZE_BASE};
    --font-size-md: {Typography.FONT_SIZE_MD};
    --font-size-lg: {Typography.FONT_SIZE_LG};
    --font-size-xl: {Typography.FONT_SIZE_XL};
    --font-size-2xl: {Typography.FONT_SIZE_2XL};
    --font-size-3xl: {Typography.FONT_SIZE_3XL};
    --font-size-4xl: {Typography.FONT_SIZE_4XL};

    /* Spacing */
    --space-1: {Spacing.SPACE_1};
    --space-2: {Spacing.SPACE_2};
    --space-3: {Spacing.SPACE_3};
    --space-4: {Spacing.SPACE_4};
    --space-5: {Spacing.SPACE_5};
    --space-6: {Spacing.SPACE_6};
    --space-8: {Spacing.SPACE_8};
    --space-10: {Spacing.SPACE_10};
    --space-12: {Spacing.SPACE_12};

    /* Shadows */
    --shadow-sm: {Shadows.SHADOW_SM};
    --shadow-default: {Shadows.SHADOW_DEFAULT};
    --shadow-md: {Shadows.SHADOW_MD};
    --shadow-lg: {Shadows.SHADOW_LG};
    --shadow-hover: {Shadows.SHADOW_HOVER};
    --shadow-focus: {Shadows.SHADOW_FOCUS};

    /* Border Radius */
    --radius-sm: {BorderRadius.RADIUS_SM};
    --radius-default: {BorderRadius.RADIUS_DEFAULT};
    --radius-md: {BorderRadius.RADIUS_MD};
    --radius-lg: {BorderRadius.RADIUS_LG};
    --radius-full: {BorderRadius.RADIUS_FULL};

    /* Transitions */
    --transition-fast: {Transitions.DURATION_FAST} {Transitions.EASING_DEFAULT};
    --transition-default: {Transitions.DURATION_DEFAULT} {Transitions.EASING_DEFAULT};
    --transition-slow: {Transitions.DURATION_SLOW} {Transitions.EASING_DEFAULT};
}}
"""
