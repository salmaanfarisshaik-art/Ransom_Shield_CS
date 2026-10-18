---
name: Midnight SOC
colors:
  surface: '#051424'
  surface-dim: '#051424'
  surface-bright: '#2c3a4c'
  surface-container-lowest: '#010f1f'
  surface-container-low: '#0d1c2d'
  surface-container: '#122131'
  surface-container-high: '#1c2b3c'
  surface-container-highest: '#273647'
  on-surface: '#d4e4fa'
  on-surface-variant: '#e4beb4'
  inverse-surface: '#d4e4fa'
  inverse-on-surface: '#233143'
  outline: '#ab8980'
  outline-variant: '#5b4039'
  surface-tint: '#ffb5a0'
  primary: '#ffb5a0'
  on-primary: '#5f1500'
  primary-container: '#ff5722'
  on-primary-container: '#541200'
  inverse-primary: '#b02f00'
  secondary: '#4ae176'
  on-secondary: '#003915'
  secondary-container: '#00b954'
  on-secondary-container: '#004119'
  tertiary: '#ffb3ad'
  on-tertiary: '#68000a'
  tertiary-container: '#ff5451'
  on-tertiary-container: '#5c0008'
  error: '#ffb4ab'
  on-error: '#690005'
  error-container: '#93000a'
  on-error-container: '#ffdad6'
  primary-fixed: '#ffdbd1'
  primary-fixed-dim: '#ffb5a0'
  on-primary-fixed: '#3b0900'
  on-primary-fixed-variant: '#862200'
  secondary-fixed: '#6bff8f'
  secondary-fixed-dim: '#4ae176'
  on-secondary-fixed: '#002109'
  on-secondary-fixed-variant: '#005321'
  tertiary-fixed: '#ffdad7'
  tertiary-fixed-dim: '#ffb3ad'
  on-tertiary-fixed: '#410004'
  on-tertiary-fixed-variant: '#930013'
  background: '#051424'
  on-background: '#d4e4fa'
  surface-variant: '#273647'
typography:
  display-lg:
    fontFamily: Inter
    fontSize: 32px
    fontWeight: '700'
    lineHeight: 40px
    letterSpacing: -0.02em
  headline-md:
    fontFamily: Inter
    fontSize: 24px
    fontWeight: '600'
    lineHeight: 32px
    letterSpacing: -0.01em
  title-sm:
    fontFamily: Inter
    fontSize: 18px
    fontWeight: '600'
    lineHeight: 24px
  body-md:
    fontFamily: Inter
    fontSize: 14px
    fontWeight: '400'
    lineHeight: 20px
  body-sm:
    fontFamily: Inter
    fontSize: 12px
    fontWeight: '400'
    lineHeight: 18px
  code-sm:
    fontFamily: JetBrains Mono
    fontSize: 12px
    fontWeight: '400'
    lineHeight: 16px
  code-xs:
    fontFamily: JetBrains Mono
    fontSize: 10px
    fontWeight: '500'
    lineHeight: 14px
    letterSpacing: 0.02em
rounded:
  sm: 0.125rem
  DEFAULT: 0.25rem
  md: 0.375rem
  lg: 0.5rem
  xl: 0.75rem
  full: 9999px
spacing:
  unit: 4px
  gutter: 12px
  margin-page: 24px
  card-padding: 16px
  density-compact: 4px
  density-comfortable: 12px
---

## Brand & Style

The design system is engineered for high-stakes cybersecurity environments where cognitive load management and rapid data synthesis are paramount. The "Midnight SOC" aesthetic prioritizes a "dark-first" interface to reduce eye strain during long shifts in Security Operations Centers.

The style is **Technical Minimalism**—a blend of Corporate Modern and high-density functional design. It avoids decorative flourishes like shadows or gradients in favor of structural clarity, utilizing crisp borders and tonal layering to define hierarchy. The emotional response is one of controlled urgency: professional, precise, and authoritative.

## Colors

This design system utilizes a high-contrast dark palette optimized for legibility of technical telemetry.

*   **Primary (Deep Orange):** Reserved for active alerts, warnings, and primary calls to action that require immediate analyst attention.
*   **Success (Terminal Green):** Indicates resolved threats, safe system states, and validated encryption keys.
*   **Destructive (Alert Red):** Strictly used for containment actions, system shutdowns, and critical breaches.
*   **Neutral (Slate):** Used for metadata, secondary labels, and inactive states to keep the focus on actionable data.
*   **Surface Logic:** Content is layered using a hierarchy of darks. The canvas is near-black, while surfaces/cards use a slightly lighter charcoal to create depth without relying on shadows.

## Typography

Typography is divided into two functional roles: **System Navigation (Inter)** and **Data Telemetry (JetBrains Mono)**.

Inter provides a highly legible, neutral foundation for headers and interface controls. JetBrains Mono is used for all "hard" data, including IP addresses, SHA-256 hashes, file paths, and logs. This distinction allows analysts to instantly differentiate between UI instructions and the technical content they are investigating. 

For mobile views, `display-lg` should scale down to 24px to ensure dashboard widgets remain visible without excessive scrolling.

## Layout & Spacing

The layout follows a **Fixed-Fluid Hybrid** model. Navigation and sidebars are fixed-width to maintain tool accessibility, while the central dashboard area is a 12-column fluid grid. 

To achieve the "data-dense" requirement, the system uses a tight 4px baseline grid. 
*   **Desktop:** 12 columns, 12px gutters, 24px outer margins.
*   **Tablet:** 6 columns, 12px gutters, 16px outer margins.
*   **Mobile:** 2 columns, 8px gutters, 12px outer margins.

Information density is increased by using `density-compact` for data tables and logs, while `density-comfortable` is reserved for settings and landing pages.

## Elevation & Depth

This design system avoids shadows to maintain a sleek, terminal-like appearance. Depth is conveyed exclusively through **Tonal Layering** and **Subtle Outlines**:

1.  **Level 0 (Canvas):** `#0a0a0b` - The base layer for the entire application.
2.  **Level 1 (Surface):** `#161618` - Used for primary cards and widgets. These must have a 1px border of `#2d2d30`.
3.  **Level 2 (Overlay):** `#1c1c1f` - Used for modals, dropdowns, and tooltips. These are slightly lighter than the surface to indicate prominence and may include a 1px border of `#3f3f46`.

Interaction states (hover/active) should be indicated by changing the border color or increasing the surface brightness, never by adding a shadow.

## Shapes

The shape language is strictly **Soft (0.25rem)**. This provides a subtle modern touch that prevents the UI from feeling "primitive" (0px) while maintaining the professional, serious tone of an enterprise security tool. 

*   **Inputs and Buttons:** 4px (0.25rem) corner radius.
*   **Cards and Containers:** 8px (0.5rem) corner radius for `rounded-lg`.
*   **Tags/Status Chips:** 4px (0.25rem) to keep them aligned with the grid; do not use pill shapes.

## Components

### Buttons
*   **Primary:** Solid Orange (#ff5722) with white text.
*   **Secondary:** Ghost style, 1px border (#2d2d30), transparent background, turns to Level 2 grey on hover.
*   **Critical:** Solid Red (#ef4444) for containment actions.

### Cards & Widgets
*   Flat background (#161618) with a 1px border (#2d2d30). Headers within cards should have a subtle bottom divider.

### Data Tables & Logs
*   Use `code-sm` typography for row content. 
*   Alternating row stripes are not used; instead, use a 1px border-bottom for each row.
*   Active/Selected rows should use a subtle Primary Orange left-border accent (3px width).

### Inputs
*   Background is darker than the surface (#0a0a0b) to create an "inset" feel. 
*   Borders transition from Neutral (#2d2d30) to Primary (#ff5722) on focus.

### Status Indicators
*   Use small square "dots" rather than circles to match the technical, grid-based aesthetic.
*   Green: Secure | Orange: Investigating | Red: Breached.