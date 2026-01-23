"""
Unified CSS Stylesheet for Mantissa Stance.

This module generates CSS stylesheets that can be used by both
the web dashboard and static HTML exports.
"""

from __future__ import annotations

from stance.ui.design_tokens import get_css_variables


def get_base_styles() -> str:
    """
    Get base CSS reset and foundation styles.

    Returns:
        CSS string with base styles
    """
    return """
/* CSS Reset & Base Styles */
*, *::before, *::after {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

html {
    font-size: 16px;
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
}

body {
    font-family: var(--font-family-sans);
    font-size: var(--font-size-base);
    line-height: 1.5;
    color: var(--color-text-primary);
    background-color: var(--color-bg-primary);
}

img, svg {
    display: block;
    max-width: 100%;
}

button {
    font-family: inherit;
    font-size: inherit;
    cursor: pointer;
}

a {
    color: var(--color-brand-primary);
    text-decoration: none;
}

a:hover {
    text-decoration: underline;
}

/* Scrollbar Styling */
::-webkit-scrollbar {
    width: 8px;
    height: 8px;
}

::-webkit-scrollbar-track {
    background: var(--color-bg-secondary);
}

::-webkit-scrollbar-thumb {
    background: var(--color-border-dark);
    border-radius: var(--radius-full);
}

::-webkit-scrollbar-thumb:hover {
    background: var(--color-text-muted);
}
"""


def get_component_styles() -> str:
    """
    Get component-specific CSS styles.

    Returns:
        CSS string with component styles
    """
    return """
/* ============================================
   Layout Components
   ============================================ */

.stance-container {
    max-width: 1400px;
    margin: 0 auto;
    padding: var(--space-6);
}

.stance-container--fluid {
    max-width: 100%;
}

.stance-grid {
    display: grid;
    gap: var(--space-4);
}

.stance-grid--2 { grid-template-columns: repeat(2, 1fr); }
.stance-grid--3 { grid-template-columns: repeat(3, 1fr); }
.stance-grid--4 { grid-template-columns: repeat(4, 1fr); }
.stance-grid--auto { grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); }

.stance-flex {
    display: flex;
    gap: var(--space-4);
}

.stance-flex--between {
    justify-content: space-between;
    align-items: center;
}

.stance-flex--center {
    justify-content: center;
    align-items: center;
}

/* ============================================
   Header Component
   ============================================ */

.stance-header {
    background: linear-gradient(135deg, var(--color-brand-secondary) 0%, var(--color-brand-primary) 100%);
    color: var(--color-text-inverse);
    padding: var(--space-8);
    margin: calc(var(--space-6) * -1);
    margin-bottom: var(--space-6);
}

.stance-header__title {
    font-size: var(--font-size-3xl);
    font-weight: 600;
    margin-bottom: var(--space-2);
    letter-spacing: -0.025em;
}

.stance-header__subtitle {
    font-size: var(--font-size-md);
    opacity: 0.9;
}

.stance-header__meta {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-5);
    margin-top: var(--space-3);
    font-size: var(--font-size-sm);
    opacity: 0.85;
}

.stance-header__meta-item {
    display: flex;
    align-items: center;
    gap: var(--space-2);
}

/* ============================================
   Summary Cards
   ============================================ */

.stance-summary-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: var(--space-4);
    margin-bottom: var(--space-6);
}

.stance-card {
    background: var(--color-bg-primary);
    border: 1px solid var(--color-border-default);
    border-radius: var(--radius-md);
    padding: var(--space-5);
    transition: var(--transition-default);
}

.stance-card:hover {
    box-shadow: var(--shadow-hover);
}

.stance-card--summary {
    text-align: center;
}

.stance-card__value {
    font-size: var(--font-size-4xl);
    font-weight: 700;
    line-height: 1.1;
    margin-bottom: var(--space-1);
}

.stance-card__label {
    font-size: var(--font-size-sm);
    color: var(--color-text-secondary);
}

.stance-card__trend {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: var(--space-1);
    margin-top: var(--space-2);
    font-size: var(--font-size-xs);
}

.stance-card__trend--up { color: var(--color-error); }
.stance-card__trend--down { color: var(--color-success); }
.stance-card__trend--stable { color: var(--color-text-muted); }

/* Card color variants */
.stance-card--critical .stance-card__value { color: var(--color-critical); }
.stance-card--high .stance-card__value { color: var(--color-high); }
.stance-card--medium .stance-card__value { color: var(--color-medium); }
.stance-card--low .stance-card__value { color: var(--color-low); }
.stance-card--success .stance-card__value { color: var(--color-success); }

/* ============================================
   Badges
   ============================================ */

.stance-badge {
    display: inline-flex;
    align-items: center;
    padding: 0.25rem 0.625rem;
    font-size: var(--font-size-xs);
    font-weight: 600;
    border-radius: var(--radius-sm);
    text-transform: uppercase;
    letter-spacing: 0.025em;
    white-space: nowrap;
}

.stance-badge--critical {
    background: var(--color-critical-bg);
    color: var(--color-critical);
    border: 1px solid var(--color-critical-border);
}

.stance-badge--high {
    background: var(--color-high-bg);
    color: var(--color-high);
    border: 1px solid var(--color-high-border);
}

.stance-badge--medium {
    background: var(--color-medium-bg);
    color: var(--color-medium);
    border: 1px solid var(--color-medium-border);
}

.stance-badge--low {
    background: var(--color-low-bg);
    color: var(--color-low);
    border: 1px solid var(--color-low-border);
}

.stance-badge--info {
    background: var(--color-info-bg);
    color: var(--color-info);
    border: 1px solid var(--color-info-border);
}

/* Status badges */
.stance-status {
    display: inline-flex;
    align-items: center;
    gap: var(--space-2);
    padding: 0.25rem 0.625rem;
    font-size: var(--font-size-xs);
    font-weight: 500;
    border-radius: var(--radius-sm);
}

.stance-status__dot {
    width: 8px;
    height: 8px;
    border-radius: var(--radius-full);
    background: currentColor;
}

.stance-status--open {
    background: var(--color-status-open-bg);
    color: var(--color-status-open);
}

.stance-status--resolved {
    background: var(--color-status-resolved-bg);
    color: var(--color-status-resolved);
}

.stance-status--suppressed {
    background: var(--color-status-suppressed-bg);
    color: var(--color-status-suppressed);
}

.stance-status--false-positive {
    background: var(--color-status-false-positive-bg);
    color: var(--color-status-false-positive);
}

/* ============================================
   Tabs Component
   ============================================ */

.stance-tabs {
    border-bottom: 2px solid var(--color-border-default);
    margin-bottom: var(--space-6);
    display: flex;
    gap: var(--space-1);
    overflow-x: auto;
}

.stance-tabs__tab {
    padding: var(--space-3) var(--space-5);
    font-size: var(--font-size-base);
    font-weight: 500;
    color: var(--color-text-secondary);
    background: none;
    border: none;
    border-bottom: 2px solid transparent;
    margin-bottom: -2px;
    transition: var(--transition-default);
    white-space: nowrap;
}

.stance-tabs__tab:hover {
    color: var(--color-text-primary);
    background: var(--color-bg-secondary);
}

.stance-tabs__tab--active {
    color: var(--color-brand-primary);
    border-bottom-color: var(--color-brand-primary);
}

.stance-tabs__tab-count {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    min-width: 1.5rem;
    height: 1.25rem;
    padding: 0 0.375rem;
    margin-left: var(--space-2);
    font-size: var(--font-size-xs);
    font-weight: 600;
    background: var(--color-bg-tertiary);
    border-radius: var(--radius-full);
}

.stance-tabs__tab--active .stance-tabs__tab-count {
    background: var(--color-brand-primary);
    color: var(--color-text-inverse);
}

.stance-tab-content {
    display: none;
}

.stance-tab-content--active {
    display: block;
    animation: fadeIn 0.2s ease-out;
}

@keyframes fadeIn {
    from { opacity: 0; transform: translateY(4px); }
    to { opacity: 1; transform: translateY(0); }
}

/* ============================================
   Data Tables
   ============================================ */

.stance-table-container {
    overflow-x: auto;
    border-radius: var(--radius-md);
    box-shadow: var(--shadow-default);
}

.stance-table {
    width: 100%;
    border-collapse: collapse;
    background: var(--color-bg-primary);
}

.stance-table th {
    background: var(--color-bg-secondary);
    font-size: var(--font-size-xs);
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--color-text-secondary);
    text-align: left;
    padding: var(--space-3) var(--space-4);
    border-bottom: 2px solid var(--color-border-default);
    white-space: nowrap;
}

.stance-table th--sortable {
    cursor: pointer;
    user-select: none;
}

.stance-table th--sortable:hover {
    color: var(--color-text-primary);
}

.stance-table td {
    padding: var(--space-3) var(--space-4);
    border-bottom: 1px solid var(--color-border-default);
    vertical-align: top;
}

.stance-table tr:last-child td {
    border-bottom: none;
}

.stance-table tr:hover {
    background: var(--color-bg-secondary);
}

.stance-table__title {
    font-weight: 500;
    color: var(--color-text-primary);
}

.stance-table__subtitle {
    font-size: var(--font-size-xs);
    color: var(--color-text-secondary);
    margin-top: var(--space-1);
}

/* ============================================
   Finding Cards
   ============================================ */

.stance-finding {
    background: var(--color-bg-primary);
    border: 1px solid var(--color-border-default);
    border-radius: var(--radius-md);
    padding: var(--space-5);
    margin-bottom: var(--space-4);
    transition: var(--transition-default);
}

.stance-finding:hover {
    border-color: var(--color-border-dark);
    box-shadow: var(--shadow-sm);
}

.stance-finding--critical { border-left: 4px solid var(--color-critical); }
.stance-finding--high { border-left: 4px solid var(--color-high); }
.stance-finding--medium { border-left: 4px solid var(--color-medium); }
.stance-finding--low { border-left: 4px solid var(--color-low); }
.stance-finding--info { border-left: 4px solid var(--color-info); }

.stance-finding__header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: var(--space-4);
    margin-bottom: var(--space-3);
}

.stance-finding__title {
    font-size: var(--font-size-md);
    font-weight: 600;
    color: var(--color-text-primary);
    flex: 1;
}

.stance-finding__badges {
    display: flex;
    gap: var(--space-2);
    flex-shrink: 0;
}

.stance-finding__meta {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-4);
    font-size: var(--font-size-sm);
    color: var(--color-text-secondary);
    margin-bottom: var(--space-3);
}

.stance-finding__meta-item {
    display: flex;
    align-items: center;
    gap: var(--space-1);
}

.stance-finding__description {
    font-size: var(--font-size-base);
    color: var(--color-text-primary);
    line-height: 1.6;
}

.stance-finding__remediation {
    margin-top: var(--space-4);
    padding: var(--space-3) var(--space-4);
    background: var(--color-info-bg);
    border-radius: var(--radius-default);
    font-size: var(--font-size-sm);
}

.stance-finding__remediation-title {
    font-weight: 600;
    color: var(--color-brand-primary-dark);
    margin-bottom: var(--space-1);
}

/* ============================================
   Section Headers
   ============================================ */

.stance-section {
    margin-bottom: var(--space-6);
}

.stance-section__header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding-bottom: var(--space-3);
    margin-bottom: var(--space-4);
    border-bottom: 1px solid var(--color-border-default);
}

.stance-section__title {
    font-size: var(--font-size-lg);
    font-weight: 600;
    color: var(--color-text-primary);
}

.stance-section__count {
    background: var(--color-bg-secondary);
    padding: var(--space-1) var(--space-3);
    border-radius: var(--radius-full);
    font-size: var(--font-size-sm);
    font-weight: 500;
    color: var(--color-text-secondary);
}

/* ============================================
   Charts & Visualizations
   ============================================ */

.stance-chart {
    background: var(--color-bg-primary);
    border: 1px solid var(--color-border-default);
    border-radius: var(--radius-md);
    padding: var(--space-5);
    margin-bottom: var(--space-6);
}

.stance-chart__title {
    font-size: var(--font-size-md);
    font-weight: 600;
    margin-bottom: var(--space-4);
}

.stance-severity-bar {
    display: flex;
    height: 2rem;
    border-radius: var(--radius-default);
    overflow: hidden;
    margin: var(--space-4) 0;
}

.stance-severity-bar__segment {
    display: flex;
    align-items: center;
    justify-content: center;
    color: var(--color-text-inverse);
    font-size: var(--font-size-xs);
    font-weight: 600;
    min-width: 2.5rem;
    transition: var(--transition-default);
}

.stance-severity-bar__segment:hover {
    filter: brightness(1.1);
}

.stance-severity-bar__segment--critical { background: var(--color-critical); }
.stance-severity-bar__segment--high { background: var(--color-high); }
.stance-severity-bar__segment--medium { background: var(--color-medium); }
.stance-severity-bar__segment--low { background: var(--color-low); }
.stance-severity-bar__segment--info { background: var(--color-info); }

.stance-legend {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-4);
    margin-top: var(--space-3);
}

.stance-legend__item {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    font-size: var(--font-size-sm);
}

.stance-legend__color {
    width: 14px;
    height: 14px;
    border-radius: var(--radius-sm);
}

/* Status Summary Grid */
.stance-status-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: var(--space-3);
}

.stance-status-card {
    background: var(--color-bg-primary);
    border: 1px solid var(--color-border-default);
    border-radius: var(--radius-md);
    padding: var(--space-4);
    text-align: center;
}

.stance-status-card__value {
    font-size: var(--font-size-3xl);
    font-weight: 700;
    line-height: 1.2;
}

.stance-status-card__label {
    font-size: var(--font-size-xs);
    color: var(--color-text-secondary);
    margin-top: var(--space-1);
}

.stance-status-card--open .stance-status-card__value { color: var(--color-status-open); }
.stance-status-card--resolved .stance-status-card__value { color: var(--color-status-resolved); }
.stance-status-card--suppressed .stance-status-card__value { color: var(--color-status-suppressed); }
.stance-status-card--false-positive .stance-status-card__value { color: var(--color-status-false-positive); }

/* Progress/Compliance Bars */
.stance-progress {
    display: flex;
    align-items: center;
    gap: var(--space-3);
}

.stance-progress__bar {
    flex: 1;
    height: 10px;
    background: var(--color-bg-tertiary);
    border-radius: var(--radius-full);
    overflow: hidden;
}

.stance-progress__fill {
    height: 100%;
    border-radius: var(--radius-full);
    transition: width 0.3s ease-out;
}

.stance-progress__fill--success { background: var(--color-success); }
.stance-progress__fill--warning { background: var(--color-warning); }
.stance-progress__fill--error { background: var(--color-error); }

.stance-progress__value {
    font-weight: 600;
    min-width: 3rem;
    text-align: right;
}

/* ============================================
   Empty States
   ============================================ */

.stance-empty {
    text-align: center;
    padding: var(--space-12) var(--space-6);
    color: var(--color-text-secondary);
}

.stance-empty__icon {
    font-size: var(--font-size-4xl);
    margin-bottom: var(--space-4);
    opacity: 0.5;
}

.stance-empty__title {
    font-size: var(--font-size-md);
    font-weight: 500;
    margin-bottom: var(--space-2);
}

.stance-empty__description {
    font-size: var(--font-size-sm);
}

/* ============================================
   Footer
   ============================================ */

.stance-footer {
    margin-top: var(--space-10);
    padding-top: var(--space-5);
    border-top: 1px solid var(--color-border-default);
    text-align: center;
    color: var(--color-text-secondary);
    font-size: var(--font-size-xs);
}

.stance-footer__brand {
    font-weight: 600;
    color: var(--color-text-primary);
}

/* ============================================
   Utility Classes
   ============================================ */

.stance-text-critical { color: var(--color-critical); }
.stance-text-high { color: var(--color-high); }
.stance-text-medium { color: var(--color-medium); }
.stance-text-low { color: var(--color-low); }
.stance-text-success { color: var(--color-success); }
.stance-text-muted { color: var(--color-text-muted); }

.stance-truncate {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
}

.stance-sr-only {
    position: absolute;
    width: 1px;
    height: 1px;
    padding: 0;
    margin: -1px;
    overflow: hidden;
    clip: rect(0, 0, 0, 0);
    white-space: nowrap;
    border-width: 0;
}

/* ============================================
   Micro-interactions & Animations
   ============================================ */

@keyframes fadeIn {
    from { opacity: 0; transform: translateY(4px); }
    to { opacity: 1; transform: translateY(0); }
}

@keyframes countUp {
    from { opacity: 0; transform: translateY(10px); }
    to { opacity: 1; transform: translateY(0); }
}

@keyframes pulse {
    0%, 100% { transform: scale(1); }
    50% { transform: scale(1.05); }
}

/* Animated metric values */
.stance-card__value {
    animation: countUp 0.4s ease-out;
    transition: transform 0.3s ease;
}

.stance-card:hover .stance-card__value {
    transform: scale(1.05);
}

/* Enhanced card hover */
.stance-card {
    transition: transform 0.2s ease, box-shadow 0.2s ease, border-color 0.2s ease;
}

.stance-card:hover {
    transform: translateY(-2px);
    box-shadow: var(--shadow-md);
    border-color: var(--color-border-dark);
}

/* Enhanced finding card */
.stance-finding {
    transition: transform 0.2s ease, box-shadow 0.2s ease;
}

.stance-finding:hover {
    transform: translateY(-2px);
    box-shadow: var(--shadow-md);
}

/* Badge hover effect */
.stance-badge {
    transition: transform 0.15s ease, box-shadow 0.15s ease;
}

.stance-badge:hover {
    transform: translateY(-1px);
    box-shadow: var(--shadow-sm);
}

/* Tab content animation */
.stance-tab-content--active {
    animation: fadeIn 0.2s ease-out;
}

/* Status dot pulse for open issues */
.stance-status--open .stance-status__dot {
    animation: pulse 2s infinite;
}

/* Severity bar segment hover */
.stance-severity-bar__segment {
    transition: filter 0.2s ease, transform 0.2s ease;
    cursor: pointer;
}

.stance-severity-bar__segment:hover {
    transform: scaleY(1.15);
    filter: brightness(1.15);
}

/* Table row transitions */
.stance-table tr {
    transition: background-color 0.15s ease;
}

/* Tab hover */
.stance-tabs__tab {
    transition: color 0.15s ease, background-color 0.15s ease, border-color 0.15s ease;
}

/* Chart hover */
.stance-chart {
    transition: box-shadow 0.2s ease;
}

.stance-chart:hover {
    box-shadow: var(--shadow-md);
}

/* Progress bar glow */
.stance-progress__fill--success {
    box-shadow: 0 0 8px rgba(22, 163, 74, 0.4);
}

.stance-progress__fill--warning {
    box-shadow: 0 0 8px rgba(202, 138, 4, 0.4);
}

.stance-progress__fill--error {
    box-shadow: 0 0 8px rgba(220, 38, 38, 0.4);
}

/* ============================================
   Responsive Adjustments
   ============================================ */

@media (max-width: 768px) {
    .stance-container {
        padding: var(--space-4);
    }

    .stance-header {
        padding: var(--space-5);
        margin: calc(var(--space-4) * -1);
        margin-bottom: var(--space-4);
    }

    .stance-header__title {
        font-size: var(--font-size-2xl);
    }

    .stance-summary-grid {
        grid-template-columns: repeat(2, 1fr);
    }

    .stance-tabs {
        flex-wrap: nowrap;
        -webkit-overflow-scrolling: touch;
    }

    .stance-tabs__tab {
        padding: var(--space-2) var(--space-3);
        font-size: var(--font-size-sm);
    }

    .stance-finding__header {
        flex-direction: column;
    }

    .stance-finding__badges {
        order: -1;
    }

    .stance-grid--2,
    .stance-grid--3,
    .stance-grid--4 {
        grid-template-columns: 1fr;
    }
}
"""


def get_print_styles() -> str:
    """
    Get print-specific CSS styles.

    Returns:
        CSS string with print styles
    """
    return """
/* ============================================
   Print Styles
   ============================================ */

@media print {
    * {
        -webkit-print-color-adjust: exact !important;
        print-color-adjust: exact !important;
    }

    body {
        font-size: 11pt;
        line-height: 1.4;
    }

    .stance-container {
        max-width: 100%;
        padding: 0;
    }

    .stance-header {
        margin: 0 0 20pt 0;
        padding: 20pt;
        page-break-after: avoid;
    }

    .stance-tabs {
        display: none;
    }

    .stance-tab-content {
        display: block !important;
        page-break-before: auto;
    }

    .stance-tab-content:not(:first-of-type) {
        page-break-before: always;
    }

    .stance-section {
        page-break-inside: avoid;
    }

    .stance-finding {
        page-break-inside: avoid;
        box-shadow: none;
        border: 1pt solid var(--color-border-default);
    }

    .stance-card {
        box-shadow: none;
        border: 1pt solid var(--color-border-default);
    }

    .stance-table {
        font-size: 10pt;
    }

    .stance-table tr {
        page-break-inside: avoid;
    }

    .stance-footer {
        position: fixed;
        bottom: 0;
        width: 100%;
        border-top: 1pt solid var(--color-border-default);
        padding-top: 10pt;
    }

    .no-print,
    .stance-tabs__tab-count {
        display: none !important;
    }

    a {
        color: var(--color-text-primary);
        text-decoration: none;
    }

    a[href]::after {
        content: " (" attr(href) ")";
        font-size: 9pt;
        color: var(--color-text-muted);
    }

    a[href^="#"]::after,
    a[href^="javascript"]::after {
        content: "";
    }
}

@page {
    margin: 0.75in;
}

@page :first {
    margin-top: 0;
}
"""


def get_full_stylesheet() -> str:
    """
    Get the complete CSS stylesheet including all components.

    Returns:
        Complete CSS string
    """
    return f"""
/* Mantissa Stance Design System v1.0 */
/* Generated stylesheet - do not edit directly */

{get_css_variables()}
{get_base_styles()}
{get_component_styles()}
{get_print_styles()}
"""


def get_stylesheet_for_embed() -> str:
    """
    Get stylesheet suitable for embedding in HTML exports.

    This version is minified and includes all necessary styles.

    Returns:
        CSS string suitable for embedding
    """
    # For now, return the full stylesheet
    # In production, this could be minified
    return get_full_stylesheet()
