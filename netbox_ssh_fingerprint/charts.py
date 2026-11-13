"""
Small donut charts as inline SVG, rendered on the server: no JavaScript, works in light and dark mode.
"""
import math
from html import escape

from django.utils.safestring import mark_safe

# Tabler colors as used by NetBox
COLORS = {
    'green': '#2fb344', 'blue': '#206bc4', 'cyan': '#17a2b8', 'purple': '#ae3ec9', 'yellow': '#f59f00',
    'orange': '#f76707', 'red': '#d63939', 'gray': '#868e96',
}
CATEGORICAL = ('blue', 'cyan', 'purple', 'green', 'yellow', 'gray')


def _arc(cx, cy, r_out, r_in, start, end):
    """
    Path of a donut segment from angle start to end (radians, 0 = top, clockwise).
    """
    def point(r, a):
        return cx + r * math.sin(a), cy - r * math.cos(a)

    large = 1 if end - start > math.pi else 0
    x0, y0 = point(r_out, start)
    x1, y1 = point(r_out, end)
    x2, y2 = point(r_in, end)
    x3, y3 = point(r_in, start)
    return (f'M{x0:.2f},{y0:.2f} A{r_out},{r_out} 0 {large} 1 {x1:.2f},{y1:.2f} '
            f'L{x2:.2f},{y2:.2f} A{r_in},{r_in} 0 {large} 0 {x3:.2f},{y3:.2f} Z')


def donut(slices, size=120):
    """
    slices: [(label, value, color name)]. Returns the SVG and the legend rows (label, value, percent, color).
    """
    slices = [(label, value, color) for label, value, color in slices if value]
    total = sum(v for _, v, _ in slices)
    cx = cy = size / 2
    r_out, r_in = size / 2 - 2, size / 2 - 20
    parts = []
    legend = []
    angle = 0.0
    for label, value, color in slices:
        hex_ = COLORS.get(color, color)
        share = value / total
        title = f'<title>{escape(label)}: {value} ({share:.0%})</title>'
        if share >= 0.9999:  # a full ring cannot be drawn as one arc
            parts.append(f'<circle cx="{cx}" cy="{cy}" r="{(r_out + r_in) / 2}" fill="none" stroke="{hex_}" '
                         f'stroke-width="{r_out - r_in}">{title}</circle>')
        else:
            end = angle + share * 2 * math.pi
            parts.append(f'<path d="{_arc(cx, cy, r_out, r_in, angle, end)}" fill="{hex_}">{title}</path>')
            angle = end
        legend.append((label, value, round(share * 100), hex_))
    if not total:
        parts.append(f'<circle cx="{cx}" cy="{cy}" r="{(r_out + r_in) / 2}" fill="none" stroke="currentColor" '
                     f'stroke-opacity=".15" stroke-width="{r_out - r_in}"/>')
    parts.append(f'<text x="{cx}" y="{cy}" text-anchor="middle" dominant-baseline="central" '
                 f'font-size="20" font-weight="600" fill="currentColor">{total}</text>')
    svg = (f'<svg viewBox="0 0 {size} {size}" width="{size}" height="{size}" role="img" '
           f'style="flex-shrink:0">{"".join(parts)}</svg>')
    return {'svg': mark_safe(svg), 'legend': legend, 'total': total}


def top_n(counter, n=5, other='other'):
    """
    The n largest entries of a Counter plus the rest summed up, as donut slices with categorical colors.
    """
    items = counter.most_common()
    head, tail = items[:n], items[n:]
    slices = [(label, value, CATEGORICAL[i % len(CATEGORICAL)]) for i, (label, value) in enumerate(head)]
    if tail:
        slices.append((other, sum(v for _, v in tail), 'gray'))
    return slices
