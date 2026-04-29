# Claude Code – Frontend Design Standards

## Purpose
This file prevents "AI slop" — the generic, statistically-safe aesthetic Claude defaults to when given no direction. Every frontend task must follow these rules. They apply automatically; you do not need to invoke them manually.

---

## ⚠️ MANDATORY: Design Direction Before Code

Before writing **any** frontend code, state the following in 2–3 sentences:

1. **Aesthetic direction** — commit to a specific tone (e.g. "editorial brutalism with high contrast and monospace type", "solarpunk warmth with organic shapes and earth tones", "dark luxury with gold accents and serif typography")
2. **The one memorable element** — what will a user remember about this interface 10 minutes after seeing it?
3. **Font pairing choice** — name the specific fonts and explain the pairing logic

This step is not optional. Skipping it produces generic output.

---

## Frontend Aesthetics

<frontend_aesthetics>
You tend to converge toward generic, "on distribution" outputs. In frontend design, this creates what users call the "AI slop" aesthetic. Avoid this: make creative, distinctive frontends that surprise and delight.

### Typography

Typography instantly signals quality. Avoid boring, generic fonts.

**Never use:** Inter, Roboto, Open Sans, Lato, Arial, system-ui, or default system fonts.

**Strong choices by aesthetic:**
- Code / technical: JetBrains Mono, Fira Code, IBM Plex Mono
- Editorial / long-form: Playfair Display, Crimson Pro, Fraunces, Newsreader
- Modern startup: Clash Display, Satoshi, Cabinet Grotesk, Bricolage Grotesque
- Technical / clean: IBM Plex Sans, Source Sans 3
- Distinctive / expressive: Obviously, Canela, Recoleta, PP Editorial New

**Pairing principle:** High contrast = interesting. Try display + monospace, or serif + geometric sans, or a variable font pushed to its weight extremes.

**Use weight extremes:** 100–200 vs 800–900, not 400 vs 600. Size ratios of 3x+, not 1.5x. Pick one distinctive font and use it decisively. Load from Google Fonts or Bunny Fonts.

State your font choice before writing code.

### Color & Theme

Commit to a cohesive aesthetic. Use CSS custom properties (`--color-*`) for all palette values.

- Dominant colors with sharp, unexpected accents outperform timid, evenly-distributed palettes
- One dominant hue, one strong accent, one neutral — not five equal tones
- Draw from IDE themes (Dracula, Nord, Gruvbox, Tokyo Night, Catppuccin), cultural movements (Bauhaus, Memphis, Y2K, Brutalism), or material worlds (oxidized copper, aged paper, volcanic glass)
- Alternate freely between dark and light themes — avoid defaulting to white backgrounds

**Never use:** purple gradients on white, teal-on-dark-grey, generic "startup blue"

### Spatial Composition & Layout

Layout is where generic feeling actually comes from. Break predictable patterns:

- Use **asymmetry** deliberately — not everything center-aligned
- **Overlap elements** — let components bleed across grid lines
- **Diagonal flow**, rotated type, or angled dividers where appropriate
- **Grid-breaking heroes** — full-bleed images or text that escapes the container
- Choose between **generous negative space** OR **controlled density** — never the uncomfortable middle ground of "a bit of padding everywhere"
- Avoid: card-grid monotony, equal-column layouts, centered-everything, cookie-cutter hero + features + CTA structure

### Motion & Animation

Focus on high-impact moments, not scattered micro-interactions.

- One well-orchestrated page load with staggered reveals (`animation-delay`) creates more delight than dozens of hover effects
- CSS-only solutions preferred for HTML; Motion library for React (`import { motion } from "motion/react"`)
- Scroll-triggered entrance animations on key content sections
- Hover states that feel physically satisfying — transforms, reveals, not just color fades
- Respect `prefers-reduced-motion` in all animation code

### Backgrounds & Depth

Never default to flat solid colors.

**Create atmosphere with:**
- Layered CSS gradients (radial + linear combined)
- `background-image: url("data:image/svg+xml,...")` for geometric SVG patterns inline
- CSS noise grain overlays using `filter: url(#noise)` or pseudo-element with turbulence filter
- Gradient meshes using multiple radial-gradient layers at different positions
- Dramatic box-shadows, glows, and inner shadows for depth
- Glassmorphism (`backdrop-filter: blur`) used sparingly and intentionally

### What to Actively Avoid

- Overused font families (Inter, Roboto, Arial, system fonts)
- Purple gradients on white backgrounds
- Teal / cyan on dark grey
- Generic "saas blue" color schemes
- Predictable card-grid layouts
- Cookie-cutter hero sections
- Space Grotesk (overused across Claude generations — avoid it)
- Balanced, timid, inoffensive palettes
- Designs that could belong to any company in any industry

</frontend_aesthetics>

---

## Isolated Dimension Prompts

Use these when you want to fix one specific thing without changing everything else.

### Typography Only
When improving typography without touching layout or color:
- Name the font before writing any CSS
- Apply weight extremes (200 vs 800)
- Set a type scale with jumps of at least 3x between headline and body
- Use `font-feature-settings` for ligatures and oldstyle figures where appropriate

### Theme Constraint
When a specific brand or aesthetic is required, name it explicitly and derive all decisions from it. Examples:
- "Nordic brutalism" → stark whites, black ink, condensed grotesque type, no gradients
- "Solarpunk" → warm greens and golds, organic curves, retro-futuristic display type
- "Terminal hacker" → monospace everything, green-on-black or amber-on-black, scanline effects

### Motion Only
When adding animation to an existing design without restyling:
- Identify the 2–3 highest-impact moments (page load, primary CTA, key data reveal)
- Write a single orchestrated entrance sequence with `animation-delay` offsets
- Add one satisfying hover state on the primary interactive element
- Leave everything else static

---

## Skills to Install

The following Claude Code skills are widely recommended by the community for UI quality. Install them alongside this CLAUDE.md for a complete frontend design workflow:

### Official Anthropic Skills
```bash
# The foundational design skill — install on every frontend project
npx skills add anthropics/claude-code --skill frontend-design
```

### Community Skills (Highly Rated)

**`ui-skills` pack** — 4 complementary skills that chain into a full UI quality workflow:
```bash
npx ui-skills add baseline-ui          # removes agent UI slop, fixes spacing/typography
npx ui-skills add fixing-accessibility # WCAG 2.1 A/AA: keyboard nav, labels, focus, semantics
npx ui-skills add fixing-motion-performance  # performance-first motion + reduced-motion
npx ui-skills add fixing-metadata      # meta tags, OG images, structured data
```
Recommended workflow: `/frontend-design` → `/baseline-ui` → `/fixing-accessibility` → `/fixing-motion-performance`

**`bencium/bencium-claude-code-design-skill`** — the most thorough UX design reference in the ecosystem (28,000+ chars). Two modes:
- `bencium-innovative-ux-designer` — bold, creative, distinctive (use for new greenfield work)
- `bencium-controlled-ux-designer` — consistency and control (use for design system maintenance)
```bash
npx skills add bencium/bencium-claude-code-design-skill
```

**`accesslint` plugin** — dedicated accessibility toolkit with 4 skills and a bundled MCP server for programmatic color contrast analysis. Install if accessibility compliance is a requirement:
```bash
npx skills add accesslint/claude-marketplace
```

### Skill Workflow for New Pages
```
/frontend-design Build @src/pages/<PageName> 
Stack: [your stack here]
Needs: [layout requirements, a11y needs, animation intent]
After writing code:
1) /baseline-ui @src/pages/<PageName>
2) /fixing-accessibility @src/pages/<PageName>
3) /fixing-motion-performance @src/pages/<PageName>
```

---

## Design Vocabulary Reference

Use these terms when briefing Claude on aesthetic direction. The more specific, the better.

| Category | Options |
|---|---|
| Brutalist | Raw, structural, anti-decorative, exposed grid, heavy borders |
| Editorial | Magazine-style, large typographic hierarchy, white space as a design element |
| Luxury | Restraint, serif type, gold/cream/black, nothing superfluous |
| Maximalist | Dense, layered, saturated, every surface designed |
| Retro-futuristic | CRT effects, scanlines, terminal aesthetics, neon |
| Organic | Curved shapes, earthy palette, nature-inspired textures |
| Glassy | Transparency, blur, refracted light, material depth |
| Industrial | Monochrome, mechanical details, functional beauty |

---

## Quick Anti-Slop Checklist

Before submitting any frontend output, verify:

- [ ] Font is NOT Inter, Roboto, Arial, Open Sans, or Space Grotesk
- [ ] Background is NOT a plain white or plain dark solid color
- [ ] Color palette has a dominant hue + sharp accent, not 5 equal tones
- [ ] Layout has at least one asymmetric or grid-breaking element
- [ ] There is one memorable, distinctive design element
- [ ] Animation (if present) is orchestrated, not scattered
- [ ] Design direction was stated before code was written
- [ ] The design could not belong to a generic SaaS competitor
