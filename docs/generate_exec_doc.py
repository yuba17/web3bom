#!/usr/bin/env python3
"""Genera el documento Word ejecutivo-técnico del sistema de Bug Bounty Web3.

Dirigido a dirección. Lenguaje técnico con orientación de negocio.
"""
from docx import Document
from docx.shared import Pt, RGBColor, Inches
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_LINE_SPACING
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.section import WD_SECTION
from docx.oxml.ns import qn
from docx.oxml import OxmlElement

# ----------------------------------------------------------------------------
# Paleta de color corporativa
# ----------------------------------------------------------------------------
NAVY      = RGBColor(0x10, 0x2A, 0x43)   # azul marino — títulos
ACCENT    = RGBColor(0x1F, 0x6F, 0xB2)   # azul medio — subtítulos
TEAL      = RGBColor(0x0E, 0x7C, 0x86)   # verde azulado — acentos
GREY      = RGBColor(0x55, 0x55, 0x55)   # gris — texto secundario
WHITE     = RGBColor(0xFF, 0xFF, 0xFF)
HEADER_BG = "1F6FB2"
ALT_BG    = "EAF1F8"
DARK_BG   = "102A43"

doc = Document()

# ----------------------------------------------------------------------------
# Estilos base
# ----------------------------------------------------------------------------
normal = doc.styles["Normal"]
normal.font.name = "Calibri"
normal.font.size = Pt(10.5)
normal.font.color.rgb = RGBColor(0x22, 0x22, 0x22)
normal.paragraph_format.space_after = Pt(6)
normal.paragraph_format.line_spacing = 1.15


def _set_cell_bg(cell, hex_color):
    tcPr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), hex_color)
    tcPr.append(shd)


def _set_cell_margins(cell, top=60, bottom=60, left=100, right=100):
    tcPr = cell._tc.get_or_add_tcPr()
    m = OxmlElement("w:tcMar")
    for tag, val in (("top", top), ("bottom", bottom), ("start", left), ("end", right)):
        e = OxmlElement(f"w:{tag}")
        e.set(qn("w:w"), str(val))
        e.set(qn("w:type"), "dxa")
        m.append(e)
    tcPr.append(m)


def heading(text, level=1):
    p = doc.add_paragraph()
    p.paragraph_format.keep_with_next = True
    if level == 1:
        p.paragraph_format.space_before = Pt(18)
        p.paragraph_format.space_after = Pt(8)
        run = p.add_run(text)
        run.font.size = Pt(17)
        run.font.bold = True
        run.font.color.rgb = NAVY
        # borde inferior
        pPr = p._p.get_or_add_pPr()
        pbdr = OxmlElement("w:pBdr")
        bottom = OxmlElement("w:bottom")
        bottom.set(qn("w:val"), "single")
        bottom.set(qn("w:sz"), "8")
        bottom.set(qn("w:space"), "4")
        bottom.set(qn("w:color"), "1F6FB2")
        pbdr.append(bottom)
        pPr.append(pbdr)
    elif level == 2:
        p.paragraph_format.space_before = Pt(12)
        p.paragraph_format.space_after = Pt(4)
        run = p.add_run(text)
        run.font.size = Pt(13)
        run.font.bold = True
        run.font.color.rgb = ACCENT
    else:
        p.paragraph_format.space_before = Pt(8)
        p.paragraph_format.space_after = Pt(2)
        run = p.add_run(text)
        run.font.size = Pt(11)
        run.font.bold = True
        run.font.color.rgb = TEAL
    return p


def body(text, italic=False, color=None, size=10.5, space_after=6):
    p = doc.add_paragraph()
    p.paragraph_format.space_after = Pt(space_after)
    run = p.add_run(text)
    run.font.italic = italic
    run.font.size = Pt(size)
    if color:
        run.font.color.rgb = color
    return p


def bullet(text, bold_prefix=None):
    p = doc.add_paragraph(style="List Bullet")
    p.paragraph_format.space_after = Pt(3)
    if bold_prefix:
        r = p.add_run(bold_prefix)
        r.font.bold = True
        r.font.color.rgb = NAVY
        p.add_run(text)
    else:
        p.add_run(text)
    return p


def callout(title, text, bg=ALT_BG, bar=HEADER_BG):
    """Caja destacada (un único párrafo en una tabla 1x1)."""
    tbl = doc.add_table(rows=1, cols=1)
    tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    cell = tbl.cell(0, 0)
    _set_cell_bg(cell, bg)
    _set_cell_margins(cell, top=120, bottom=120, left=160, right=160)
    cell.paragraphs[0].text = ""
    p = cell.paragraphs[0]
    r = p.add_run(title)
    r.font.bold = True
    r.font.size = Pt(11)
    r.font.color.rgb = NAVY
    p2 = cell.add_paragraph()
    p2.paragraph_format.space_before = Pt(3)
    r2 = p2.add_run(text)
    r2.font.size = Pt(10)
    # barra de color a la izquierda
    tcPr = cell._tc.get_or_add_tcPr()
    borders = OxmlElement("w:tcBorders")
    left = OxmlElement("w:left")
    left.set(qn("w:val"), "single")
    left.set(qn("w:sz"), "24")
    left.set(qn("w:space"), "0")
    left.set(qn("w:color"), bar)
    borders.append(left)
    tcPr.append(borders)
    doc.add_paragraph().paragraph_format.space_after = Pt(2)
    return tbl


def make_table(headers, rows, col_widths=None, font_size=9.5):
    tbl = doc.add_table(rows=1, cols=len(headers))
    tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    tbl.style = "Table Grid"
    # cabecera
    hdr = tbl.rows[0].cells
    for i, h in enumerate(headers):
        _set_cell_bg(hdr[i], HEADER_BG)
        _set_cell_margins(hdr[i])
        para = hdr[i].paragraphs[0]
        para.alignment = WD_ALIGN_PARAGRAPH.LEFT
        run = para.add_run(h)
        run.font.bold = True
        run.font.size = Pt(font_size)
        run.font.color.rgb = WHITE
    # filas
    for ri, row in enumerate(rows):
        cells = tbl.add_row().cells
        for ci, val in enumerate(row):
            _set_cell_margins(cells[ci])
            if ri % 2 == 1:
                _set_cell_bg(cells[ci], ALT_BG)
            para = cells[ci].paragraphs[0]
            run = para.add_run(str(val))
            run.font.size = Pt(font_size)
            # primera columna en negrita
            if ci == 0:
                run.font.bold = True
                run.font.color.rgb = NAVY
    if col_widths:
        for ci, w in enumerate(col_widths):
            for cell in tbl.columns[ci].cells:
                cell.width = Inches(w)
    doc.add_paragraph().paragraph_format.space_after = Pt(2)
    return tbl


def add_page_number_footer(section):
    footer = section.footer
    p = footer.paragraphs[0]
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = p.add_run("Sistema de Bug Bounty Web3  ·  Documento confidencial  ·  Página ")
    r.font.size = Pt(8)
    r.font.color.rgb = GREY
    # campo PAGE
    fldSimple = OxmlElement("w:fldSimple")
    fldSimple.set(qn("w:instr"), "PAGE")
    run_el = OxmlElement("w:r")
    rpr = OxmlElement("w:rPr")
    sz = OxmlElement("w:sz"); sz.set(qn("w:val"), "16"); rpr.append(sz)
    run_el.append(rpr)
    t = OxmlElement("w:t"); t.text = "1"; run_el.append(t)
    fldSimple.append(run_el)
    p._p.append(fldSimple)


# ============================================================================
# PORTADA
# ============================================================================
section = doc.sections[0]
section.top_margin = Inches(1.0)
section.bottom_margin = Inches(1.0)
section.left_margin = Inches(1.0)
section.right_margin = Inches(1.0)

for _ in range(3):
    doc.add_paragraph()

p = doc.add_paragraph()
p.alignment = WD_ALIGN_PARAGRAPH.CENTER
r = p.add_run("DOCUMENTO PARA DIRECCIÓN")
r.font.size = Pt(12)
r.font.bold = True
r.font.color.rgb = TEAL
r.font.name = "Calibri"
# espaciado de letras
rPr = r._element.get_or_add_rPr()
spc = OxmlElement("w:spacing"); spc.set(qn("w:val"), "60"); rPr.append(spc)

p = doc.add_paragraph()
p.alignment = WD_ALIGN_PARAGRAPH.CENTER
p.paragraph_format.space_before = Pt(14)
r = p.add_run("Sistema Autónomo de\nBug Bounty Hunting Web3")
r.font.size = Pt(30)
r.font.bold = True
r.font.color.rgb = NAVY

p = doc.add_paragraph()
p.alignment = WD_ALIGN_PARAGRAPH.CENTER
p.paragraph_format.space_before = Pt(8)
r = p.add_run("Arquitectura, metodología y estado operativo de la plataforma\nde descubrimiento de vulnerabilidades en contratos inteligentes")
r.font.size = Pt(13)
r.font.italic = True
r.font.color.rgb = GREY

# línea separadora
p = doc.add_paragraph()
p.alignment = WD_ALIGN_PARAGRAPH.CENTER
p.paragraph_format.space_before = Pt(24)
pPr = p._p.get_or_add_pPr()
pbdr = OxmlElement("w:pBdr")
bottom = OxmlElement("w:bottom")
bottom.set(qn("w:val"), "single"); bottom.set(qn("w:sz"), "12")
bottom.set(qn("w:space"), "1"); bottom.set(qn("w:color"), "1F6FB2")
pbdr.append(bottom); pPr.append(pbdr)

for _ in range(6):
    doc.add_paragraph()

# Bloque de metadatos
meta = doc.add_table(rows=4, cols=2)
meta.alignment = WD_TABLE_ALIGNMENT.CENTER
meta_data = [
    ("Documento", "Visión técnica y de negocio del sistema"),
    ("Audiencia", "Dirección / Comité ejecutivo"),
    ("Clasificación", "Confidencial — uso interno"),
    ("Fecha", "Junio 2026  ·  Versión 1.0"),
]
for i, (k, v) in enumerate(meta_data):
    c0, c1 = meta.rows[i].cells
    _set_cell_margins(c0); _set_cell_margins(c1)
    rk = c0.paragraphs[0].add_run(k)
    rk.font.bold = True; rk.font.color.rgb = NAVY; rk.font.size = Pt(10.5)
    rv = c1.paragraphs[0].add_run(v)
    rv.font.size = Pt(10.5); rv.font.color.rgb = GREY
for col, w in zip(meta.columns, (1.6, 4.0)):
    for cell in col.cells:
        cell.width = Inches(w)

add_page_number_footer(section)
doc.add_page_break()

# ============================================================================
# ÍNDICE (manual)
# ============================================================================
heading("Índice", 1)
toc_items = [
    "1.  Resumen ejecutivo",
    "2.  Qué problema resuelve el sistema",
    "3.  Visión general de la arquitectura",
    "4.  El motor de caza: sistema multi-hunter",
    "5.  Pipeline de componente — del código al invariante",
    "6.  Pipeline de fuzzing — la prueba automatizada",
    "7.  Pipeline de finding — del hallazgo al reporte",
    "8.  Sistema de control de calidad y gates",
    "9.  Base de conocimiento y aprendizaje continuo",
    "10. Reglas de rechazo — disciplina basada en datos reales",
    "11. Stack tecnológico",
    "12. Estado operativo y resultados",
    "13. Métricas, economía y posicionamiento competitivo",
    "14. Riesgos, límites y consideraciones legales",
    "15. Hoja de ruta y conclusión",
    "Anexo A — Glosario de términos",
]
for item in toc_items:
    p = doc.add_paragraph()
    p.paragraph_format.space_after = Pt(4)
    r = p.add_run(item)
    r.font.size = Pt(11)
    if item[0].isdigit() and item[1] in ".0123456789":
        r.font.color.rgb = NAVY
doc.add_page_break()

# ============================================================================
# 1. RESUMEN EJECUTIVO
# ============================================================================
heading("1. Resumen ejecutivo", 1)
body(
    "Este documento describe, para la dirección, un sistema de software propietario "
    "cuyo objetivo de negocio es localizar vulnerabilidades en contratos inteligentes "
    "(smart contracts) de protocolos Web3 y convertir esos hallazgos en ingresos a través "
    "de programas de bug bounty y competiciones de auditoría. En este mercado, una única "
    "vulnerabilidad crítica reportada puede traducirse en recompensas de cinco a siete cifras."
)
body(
    "El sistema combina tres capacidades que, hasta hace poco, requerían equipos humanos "
    "completos: (1) generación masiva de hipótesis de ataque mediante modelos de lenguaje "
    "trabajando en paralelo como un equipo de especialistas; (2) verificación automatizada "
    "de esas hipótesis mediante “fuzzing” —pruebas que bombardean el código con millones "
    "de escenarios buscando romper sus reglas— y pruebas de concepto ejecutables; y (3) un "
    "proceso de validación disciplinado que filtra falsos positivos antes de comprometer "
    "tiempo y reputación reportando un hallazgo."
)
callout(
    "Tesis central del sistema",
    "El 80 % del conocimiento de los mejores cazadores de bugs del mundo puede codificarse "
    "en una base de conocimiento estructurada y replicarse mediante IA en N especialistas "
    "trabajando simultáneamente —algo imposible para cualquier equipo humano—. La métrica "
    "que gobierna todas las decisiones es una sola: bugs aceptados por unidad de tiempo invertido.",
    bg=ALT_BG, bar=HEADER_BG,
)
heading("Puntos clave para la dirección", 2)
bullet("opera de forma autónoma, ejecutando un pipeline de extremo a extremo con puntos de control ("
       "“gates”) que impiden avanzar si la calidad no es suficiente.", "Madurez técnica: el sistema ")
bullet("toda afirmación de vulnerabilidad debe respaldarse con una prueba de concepto "
       "ejecutable que demuestre pérdida de fondos. Sin prueba, no hay hallazgo.", "Disciplina: ")
bullet("cada rechazo real de las plataformas se convierte en una regla que evita repetir el error, "
       "y cada hallazgo confirmado enriquece la base de conocimiento.", "Aprendizaje: ")
bullet("el cuello de botella ya no es la tecnología sino la conversión de hallazgos en pagos "
       "confirmados y la cobertura de dominios de alto valor (ZK, restaking).", "Honestidad: ")

# ============================================================================
# 2. QUÉ PROBLEMA RESUELVE
# ============================================================================
heading("2. Qué problema resuelve el sistema", 1)
body(
    "Los protocolos DeFi custodian miles de millones de dólares en contratos inteligentes "
    "públicos e inmutables. Un único error de lógica —un redondeo mal direccionado, un control "
    "de acceso ausente, un oráculo de precios manipulable— puede permitir el robo de la totalidad "
    "de los fondos. Para defenderse, los protocolos publican programas de recompensa que pagan a "
    "quien encuentre y reporte estos fallos de forma responsable, antes de que lo haga un atacante."
)
body(
    "El reto del negocio es doble. Primero, el espacio de búsqueda es enorme: cada protocolo "
    "tiene miles de líneas de código y un atacante solo necesita un fallo. Segundo, la competencia "
    "es intensa y veloz: un hallazgo enviado tarde se convierte en “duplicado” sin valor. "
    "El sistema ataca ambos frentes industrializando la generación de hipótesis y su verificación, "
    "manteniendo a la vez un listón de calidad alto para no malgastar reputación en falsos positivos."
)
make_table(
    ["Categoría de bug", "Por qué importa al negocio", "Ejemplo de impacto histórico"],
    [
        ["Accounting / redondeo", "Insolvencia acumulativa: el protocolo pierde fondos lentamente", "Euler 2023 — 197 M USD"],
        ["Control de acceso", "Escalada de privilegios o robo directo", "Múltiples incidentes de 7 cifras"],
        ["Manipulación de oráculos", "Precios falsos permiten drenar pools con flash loans", "Patrón recurrente en DeFi"],
        ["Reentrancy / callbacks", "Estado desincronizado explotable en una transacción", "Histórico crítico en lending"],
        ["Cross-chain / bridges", "Replay de mensajes, DoS permanente de fondos", "Bounties de hasta 10 M USD"],
    ],
    col_widths=[1.6, 3.1, 1.9],
)
callout(
    "El foco del 80/20",
    "El 80 % de los bugs críticos se concentra en tres familias: accounting, control de acceso y "
    "manipulación de oráculos. El sistema prioriza implacablemente estos vectores antes de explorar "
    "superficies más exóticas.",
    bg="FFF4E6", bar="E8821E",
)

# ============================================================================
# 3. ARQUITECTURA GENERAL
# ============================================================================
heading("3. Visión general de la arquitectura", 1)
body(
    "El sistema se organiza en tres grandes bloques que operan en cadena. La salida de cada uno "
    "alimenta al siguiente, y los hallazgos confirmados retroalimentan la base de conocimiento, "
    "cerrando un ciclo de mejora continua."
)
make_table(
    ["Bloque", "Función", "Salida"],
    [
        ["Bounty Radar", "Monitoriza plataformas y cambios de código en los repositorios objetivo; "
         "puntúa cada oportunidad por payout, competencia, fortaleza de dominio y tiempo restante",
         "Objetivo priorizado (score 0–100): PRIORITY o SKIP"],
        ["Motor multi-hunter", "Un coordinador y 14 especialistas analizan el objetivo en paralelo, "
         "generan hipótesis de ataque, las validan y ejecutan el pipeline de fuzzing",
         "Hallazgos confirmados con prueba de concepto"],
        ["Base de conocimiento", "Briefings por dominio y fichas por protocolo; aprende de cada "
         "auditoría y de cada rechazo real de las plataformas",
         "Mejora continua de la detección"],
    ],
    col_widths=[1.5, 3.4, 1.7],
)
body(
    "El principio de diseño rector es la separación entre “generar muchas ideas” (barato, paralelizable, "
    "tolerante al ruido) y “confirmar una idea” (caro, secuencial, intolerante al error). La generación "
    "se hace con decenas de agentes a la vez; la confirmación pasa por puntos de control estrictos que "
    "impiden que un falso positivo llegue jamás a una plataforma.", space_after=8,
)
callout(
    "Modo autónomo",
    "El sistema arranca leyendo su propio estado persistente y continúa la caza sin esperar instrucción. "
    "Lee contratos, escribe invariantes, ejecuta pruebas y actualiza sus registros de forma autónoma. "
    "Solo requiere confirmación humana para tres acciones sensibles: reportar un hallazgo a una plataforma, "
    "subir cambios al repositorio, o procesar contextos masivos (más de 50 contratos).",
)

# ============================================================================
# 4. SISTEMA MULTI-HUNTER
# ============================================================================
heading("4. El motor de caza: sistema multi-hunter", 1)
body(
    "El corazón del sistema es un equipo de 14 “hunters” (cazadores) especializados que analizan cada "
    "componente de un protocolo. Doce trabajan en paralelo, cada uno experto en una familia de "
    "vulnerabilidades; dos más se ejecutan de forma secuencial al final para análisis transversal y de "
    "profundidad. Cada hunter es un agente de IA independiente con su propia ventana de contexto, que "
    "escribe sus hipótesis en su propio fichero para evitar conflictos."
)
body(
    "Cada hunter está calibrado, cuando existe, con la metodología de un referente real del sector. "
    "Antes de emitir una hipótesis, cada agente aplica un auto-filtro: “¿por qué estaría equivocado?”. "
    "Esto reduce el ruido en origen. A continuación se describe qué hace cada uno y qué busca."
)
heading("Los 12 hunters en paralelo", 2)
make_table(
    ["Hunter", "Referente", "Cómo trabaja y qué patrones prioriza"],
    [
        ["MathHunter", "Trust",
         "Identifica el invariante económico central y enumera todas las formas de alterar los activos "
         "sin alterar las participaciones (shares). Solo valida si hay pérdida concreta mayor que el coste "
         "del ataque. Patrones: truncación de redondeo acumulativa, donation attacks, deriva en el cálculo "
         "de intereses, inflación de shares, descuadres de comisiones."],
        ["AccessHunter", "Mudit Gupta",
         "Construye el grafo completo de privilegios del contrato y rastrea todos los caminos —directos e "
         "indirectos— que llevan a un rol privilegiado. Patrones: control de acceso ausente, escalada de "
         "privilegios, inicializadores desprotegidos, roles mal configurados en el despliegue."],
        ["OracleHunter", "samczsun",
         "Localiza cada punto donde se consume un precio y traza hacia atrás hasta su fuente, preguntando: "
         "“¿puede manipularse en un solo bloque y con cuánto beneficio?”. Patrones: manipulación de precio "
         "spot, TWAP con ventana insuficiente, precios obsoletos (staleness), arbitraje cross-DEX."],
        ["FlowHunter", "samczsun",
         "Trata cada llamada externa como un punto de reentrada potencial y comprueba qué estado queda "
         "desincronizado en ese instante. Verifica el orden checks-effects-interactions. Patrones: "
         "reentrancy vía callback, cross-function, read-only, abuso de callbacks de tokens (ERC-777/721)."],
        ["DomainHunter", "Variable según protocolo",
         "Aplica la lógica específica del dominio activo (staking, gauges, DEX, bridges). En staking, por "
         "ejemplo: proporcionalidad de recompensas, bugs en los límites de epoch, staking con flash loan, "
         "drenaje de recompensas antes de que los usuarios las reclamen."],
        ["TrustBoundaryHunter", "—",
         "Examina las fronteras de confianza entre el contrato y sus dependencias externas: qué asume de "
         "cada contrato con el que interactúa y qué ocurre si ese contrato se comporta de forma inesperada "
         "o maliciosa."],
        ["SignatureHunter", "—",
         "Se centra en la criptografía aplicada: replay de firmas entre contextos o cadenas, validación "
         "incorrecta de firmas, gestión de nonces y vencimientos (deadlines)."],
        ["DoSHunter", "—",
         "Busca denegación de servicio: rutas que pueden bloquearse de forma permanente, fondos que quedan "
         "atrapados sin posibilidad de recuperación, y operaciones que un atacante puede encarecer hasta "
         "hacerlas inviables."],
        ["LogicHunter", "—",
         "Caza errores de lógica de negocio y de máquina de estado: transiciones inválidas, suposiciones "
         "incorrectas sobre el orden de las operaciones y casos límite no contemplados por el diseño."],
        ["AdversarialHunter", "—",
         "Adopta la mentalidad de un atacante con capital real y motivación: no busca patrones de catálogo, "
         "sino la combinación de acciones más rentable para romper el protocolo, por exótica que sea."],
        ["LibraryHunter", "—",
         "Audita las librerías y el código reutilizado, donde los fallos heredados pasan desapercibidos por "
         "darse por “probados”. Patrones: bugs conocidos en versiones de librerías, mal uso de utilidades."],
        ["WildcardHunter", "Sin referente",
         "Su misión es encontrar lo que nadie documentó antes. Recibe la lista de hipótesis ya generadas "
         "para no repetir y piensa de forma libre. Sus hipótesis se etiquetan como “novedosas” y NUNCA se "
         "descartan por baja probabilidad."],
    ],
    col_widths=[1.35, 1.05, 3.3], font_size=8.8,
)
heading("Los 2 hunters secuenciales", 2)
body(
    "Tras los 12 hunters en paralelo se ejecutan dos hunters de forma secuencial, porque necesitan "
    "consumir el trabajo de todos los anteriores.", space_after=4,
)
bullet("solo se activa si el componente está desplegado en dos o más cadenas. Busca "
       "replay de firmas entre cadenas, divergencia de configuración, desincronización en actualizaciones "
       "de proxy y dependencias de estado cross-chain. Si el componente es de una sola cadena, se omite "
       "automáticamente.", "CrossChainHunter: ")
bullet("lee las convergencias de todos los hunters anteriores y genera hipótesis "
       "profundas, sin límite mínimo ni máximo. Puede ejecutarse en varias rondas con ángulos distintos. "
       "Prioriza calidad sobre cantidad, pero nunca corta el análisis de forma artificial. Es donde "
       "aparecen los hallazgos más sofisticados, los que los auditores anteriores pasaron por alto.",
       "DeepDiveHunter: ")
callout(
    "Por qué referentes reales",
    "Calibrar cada hunter con la metodología de un experto reconocido (samczsun para oráculos y reentrancy, "
    "Mudit Gupta para control de acceso, Trust para matemáticas) traslada conocimiento tácito difícil de "
    "codificar de otra forma. El sistema replica así, en paralelo, a un panel de especialistas que ningún "
    "equipo humano podría reunir a la vez sobre un mismo objetivo.",
)
body(
    "Las hipótesis de los 14 hunters se priorizan con una fórmula simple —severidad si es cierta × "
    "confianza × (1 / esfuerzo)— y las que cruzan varios componentes reciben prioridad alta, porque ahí es "
    "donde viven los hallazgos de mayor severidad."
)

# ============================================================================
# 5. PIPELINE DE COMPONENTE
# ============================================================================
heading("5. Pipeline de componente — del código al invariante", 1)
body(
    "Un protocolo se descompone en componentes (contratos o grupos de contratos) y se aplica una regla "
    "innegociable: un componente a la vez. No se avanza al siguiente hasta completar una lista de "
    "verificación de 12 pasos, desde la lectura íntegra del código hasta el fuzzing con al menos 5.000 "
    "iteraciones y el registro de todos los hallazgos. Esta disciplina evita el análisis superficial."
)
make_table(
    ["Fase", "Qué produce", "Control asociado"],
    [
        ["Scope", "Estado del hunt, contexto y prompts del componente", "Gate scope"],
        ["Prepass", "Análisis estático automático (Slither, Aderyn, patrones de exploit)", "Gate prepass"],
        ["12 hunters", "Hipótesis estructuradas con campos de implementación", "Gate hunters"],
        ["CrossChain / DeepDive", "Hipótesis transversales y profundas", "Gates crosschain / deepdive"],
        ["Merge", "Properties.sol y TargetFunctions.sol — invariantes en código", "Gate merge"],
        ["Compile", "Artefactos compilados listos para fuzzing", "Gate compile"],
        ["Fuzzing (5 fases)", "Evidencia de invariantes rotos = bugs", "Gates phase1–phase5"],
    ],
    col_widths=[1.7, 3.4, 1.5],
)
callout(
    "El invariante es el lenguaje del sistema",
    "Un “invariante” es una regla que el protocolo asume siempre verdadera (por ejemplo: "
    "“los activos totales nunca son menores que la deuda prestada”). El sistema traduce cada "
    "hipótesis de ataque a un invariante escrito en Solidity. Si el fuzzing consigue romperlo, ese "
    "contraejemplo ES el bug, y la secuencia que lo rompió ES la prueba de concepto.",
    bg="E8F6F4", bar="0E7C86",
)
body(
    "Cuando dos o tres componentes relacionados están completos, el sistema ejecuta automáticamente un "
    "“cross-component hunt”: mapea todas las interacciones entre ellos y busca dónde un componente asume "
    "algo sobre otro que en realidad puede fallar. Esta es una de las fuentes más fértiles de hallazgos "
    "de severidad crítica, y se hace siempre, sin que nadie lo pida."
)

# ============================================================================
# 6. PIPELINE DE FUZZING
# ============================================================================
heading("6. Pipeline de fuzzing — la prueba automatizada", 1)
body(
    "El fuzzing es la maquinaria de verificación. Cinco herramientas se ejecutan en orden secuencial "
    "—nunca en paralelo, porque comparten memoria y compilador— de modo que cada fase confirma o descarta "
    "el trabajo de la anterior. El orden está optimizado: primero la herramienta con mejor reporte de "
    "errores, y al final las que aportan valor incremental."
)
make_table(
    ["Fase", "Herramienta", "Duración", "Propósito"],
    [
        ["1", "Foundry (mock)", "5 min", "Validación rápida de invariantes; feedback inmediato"],
        ["2", "Medusa", "15 min", "Secuencias de múltiples pasos; corpus persistente"],
        ["3", "Foundry (fork real)", "10 min", "Confirma contra el estado real de mainnet; elimina falsos positivos"],
        ["4", "Echidna", "10 min", "Optimización: maximizar el beneficio del atacante"],
        ["5", "Halmos", "5 min", "Prueba simbólica formal para matemática pura"],
    ],
    col_widths=[0.6, 1.6, 1.0, 3.3],
)
callout(
    "Fork real frente a simulación",
    "El error más caro en este trabajo es el falso positivo causado por una simulación imperfecta "
    "(“mock”). Un oráculo simulado puede infravalorar posiciones; un modelo de interés simulado puede "
    "arrojar 740 % diario en lugar de 5 % anual. Por eso, para cualquier hallazgo de DeFi, la "
    "confirmación final se hace siempre sobre un “fork”: una copia local del estado real de la cadena. "
    "Esto es a la vez una garantía de calidad y de seguridad jurídica.",
    bg="FFF4E6", bar="E8821E",
)
body(
    "Entre la fase 1 y la 2 se realiza un “tolerance tuning” obligatorio: cada fallo detectado se clasifica "
    "como bug real, polvo de redondeo (“dust”), artefacto de la simulación o error de configuración. Solo los "
    "bugs reales avanzan; el resto se documenta para no volver a perseguirlo."
)

# ============================================================================
# 7. PIPELINE DE FINDING
# ============================================================================
heading("7. Pipeline de finding — del hallazgo al reporte", 1)
body(
    "Cuando un invariante se rompe y se confirma en fork, el hallazgo entra en un proceso secuencial y "
    "acumulativo de validación antes de llegar a una plataforma. Cada paso es un punto de control que "
    "debe superarse; si el control final falla, el hallazgo no se envía. Este es el mecanismo que protege "
    "la reputación del equipo y maximiza la tasa de aceptación."
)
make_table(
    ["Paso", "Control", "Qué garantiza"],
    [
        ["Prueba de concepto en fork", "poc", "Pérdida de fondos demostrada con número concreto"],
        ["EscalationHunter", "escalation", "Se exploró la máxima severidad posible (obligatorio en Medium+)"],
        ["Variant Hunt", "variant", "Se buscó el mismo patrón en otras partes del código (1 bug → 3-5 variantes)"],
        ["RedTeam (4 atacantes)", "redteam", "Cuatro perspectivas adversarias intentan refutar el hallazgo"],
        ["Verificación on-chain", "verify", "El código vulnerable está vivo y no ha sido parcheado"],
        ["ReportWriter", "report", "Reporte profesional con el formato de la plataforma"],
        ["Envío", "submit", "Registro en el radar de bounties y notificación"],
    ],
    col_widths=[1.9, 1.1, 2.7],
)
callout(
    "Reportar siempre lo verificado",
    "En plataformas con leaderboard, incluso un duplicado válido otorga puntos, construye reputación y "
    "abre programas de acceso restringido. Dado que la prueba de concepto ya existe tras el fuzzing, el "
    "coste marginal de reportar es bajo. La política es: reportar todo hallazgo verificado con prueba "
    "sólida, priorizando por severidad, no por probabilidad de ser el primero.",
    bg="E8F6F4", bar="0E7C86",
)

# ============================================================================
# 8. CONTROL DE CALIDAD Y GATES
# ============================================================================
heading("8. Sistema de control de calidad y gates", 1)
body(
    "La fiabilidad del sistema descansa sobre un componente de software llamado pipeline_gate, que actúa "
    "como “fuente de verdad”. Antes de cada transición de fase verifica que existen las evidencias "
    "requeridas. Si un gate falla, el sistema se detiene y no avanza. Esto convierte la calidad en una "
    "propiedad estructural —imposible de saltarse por prisa— en lugar de una buena intención."
)
heading("RedTeam — el adversario interno", 2)
body(
    "Todo hallazgo, sea cual sea su severidad, pasa por un ejercicio de RedTeam con cuatro atacantes que "
    "intentan demoler el caso desde ángulos distintos, más una “Ronda 0” de calibración. El veredicto solo "
    "puede ser REPORT (reportar) o descartar. Este filtro adversario interno es lo que diferencia un sistema "
    "que produce ruido de uno que produce hallazgos pagables."
)
heading("Regla FIX & RETURN", 2)
body(
    "Cuando un paso del pipeline falla, la norma operativa es quirúrgica: anotar el punto exacto, arreglar "
    "solo lo mínimo para que ese paso pase, reejecutar ese paso —no el siguiente— y continuar desde donde se "
    "quedó. Está prohibido refactorizar de paso o perder el hilo del pipeline. Tras tres intentos fallidos, "
    "el sistema se detiene y avisa. Esto evita el comportamiento errático y mantiene el avance trazable."
)

# ============================================================================
# 9. KNOWLEDGE BASE
# ============================================================================
heading("9. Base de conocimiento y aprendizaje continuo", 1)
body(
    "La ventaja competitiva sostenible del sistema no es ninguna de sus herramientas individuales, sino su "
    "base de conocimiento, organizada en dos capas que se retroalimentan."
)
bullet("conocimiento general por dominio (vaults ERC-4626, lending, oráculos, control "
       "de acceso, DEX/AMM, staking, flash loans, bridges, tokens, proxies, circuitos ZK, replay de firmas). "
       "Cada briefing contiene bugs conocidos con causa raíz, incidentes históricos, invariantes clave y —"
       "crucialmente— “trampas” que documentan por qué algo NO es un bug.", "Capa 1 — Briefings: ")
bullet("experiencia acumulada por protocolo concreto. Cuando un patrón aparece en tres o "
       "más fichas, se promueve automáticamente a un briefing general.", "Capa 2 — Fichas: ")
make_table(
    ["Fuente integrada", "Volumen"],
    [
        ["DeFiHackLabs (incidentes reales verificados)", "175+ incidentes"],
        ["Cyfrin checklist", "117 items mapeados"],
        ["Solodit (findings con contenido completo)", "483 findings"],
        ["Solodit (base completa)", "~51.000 findings"],
        ["Fichas YAML estructuradas", "180+ fichas"],
    ],
    col_widths=[3.8, 1.9],
)
callout(
    "Las “trampas” valen tanto como los bugs",
    "Documentar por qué un falso positivo fue descartado es conocimiento real y reutilizable. Un finding "
    "rechazado se convierte en una trampa que evita repetir el error; un patrón visto repetidamente se "
    "convierte en una nueva regla de detección. El sistema mejora literalmente con cada uso.",
)

# ============================================================================
# 10. REGLAS DE RECHAZO
# ============================================================================
heading("10. Reglas de rechazo — disciplina basada en datos reales", 1)
body(
    "Una de las partes más valiosas del sistema, desde la óptica de la dirección, es que aprende de los "
    "rechazos reales de las plataformas y los convierte en reglas automáticas. Antes de recomendar el envío "
    "de cualquier hallazgo, el RedTeam lo coteja contra estas reglas. Cada una nació de un rechazo concreto "
    "que costó tiempo, y existe para que ese coste no se repita."
)
make_table(
    ["Regla", "Patrón rechazado", "Origen real"],
    [
        ["R1", "El ataque requiere un rol de administrador/owner → es centralización, no vulnerabilidad",
         "Coinbase rechazó 3 de 3 hallazgos de este tipo"],
        ["R2", "Función vacía por diseño → problema de diseño, no de seguridad", "Coinbase AdConversion"],
        ["R3", "Configuración deshabilitada es señal off-chain, no un control on-chain", "Coinbase AdConversion"],
        ["R4", "La dirección del contrato no está explícitamente en el scope", "Pipeline completo gastado en dirección fuera de scope"],
        ["R5", "Impacto cosmético/UX sin fondos ni control de acceso afectados", "“No funds at risk”"],
    ],
    col_widths=[0.7, 3.3, 1.7],
)
body(
    "Antes de redactar cualquier reporte, el sistema responde un checklist obligatorio: ¿el ataque solo "
    "requiere actores no privilegiados? ¿el contrato está explícitamente en scope? ¿hay pérdida de fondos o "
    "bypass de control de acceso? ¿es un comportamiento documentado e intencional? ¿cuántos duplicados son "
    "probables? Estas preguntas, derivadas de pérdidas reales, son la mejor defensa contra el desperdicio de "
    "esfuerzo."
)

# ============================================================================
# 11. STACK TECNOLÓGICO
# ============================================================================
heading("11. Stack tecnológico", 1)
make_table(
    ["Herramienta", "Rol", "Estado"],
    [
        ["Foundry", "Framework de pruebas y fuzzing principal; fork de mainnet", "Operativo"],
        ["Medusa (Crytic)", "Fuzzing de secuencias multi-step con corpus persistente", "Operativo"],
        ["Echidna", "Fuzzing de optimización (maximizar beneficio del atacante)", "Operativo"],
        ["Halmos", "Verificación simbólica / prueba formal de matemática pura", "Operativo"],
        ["Slither / Aderyn", "Análisis estático automático en la fase de prepass", "Operativo"],
        ["Orquestación Python", "Hunters, gates, runners de fuzzing y feedback (audit-agents/)", "Operativo"],
        ["Modelos de lenguaje", "Los 14 hunters, RedTeam, ReportWriter y análisis de código", "Operativo"],
    ],
    col_widths=[1.7, 3.4, 1.1],
)
body(
    "El sistema dispone de acceso a nodos RPC de mainnet de Ethereum, Base y Optimism, lo que permite "
    "confirmar hallazgos contra el estado real de producción sin ejecutar nunca una transacción real. La "
    "suite de pruebas automatizadas del propio sistema supera las 220 pruebas, lo que da una medida de su "
    "madurez de ingeniería."
)

# ============================================================================
# 12. ESTADO OPERATIVO
# ============================================================================
heading("12. Estado operativo y resultados", 1)
body(
    "A modo de ilustración del funcionamiento real, el sistema completó recientemente la auditoría de "
    "componentes del protocolo Hyperlane (plataforma Immunefi), produciendo hallazgos confirmados con "
    "prueba de concepto en fork. El siguiente cuadro resume los hallazgos de un único componente analizado."
)
make_table(
    ["ID", "Severidad", "Título", "Pipeline"],
    [
        ["IAR-DD-01", "High", "Aprobación permisiva de token de fee permite drenaje", "7/7 completo"],
        ["IAR-DD-02", "Medium", "commitReveal drena ETH preexistente del router", "7/7 completo"],
        ["IAR-DD-03", "High", "Ataque de redirección CCIP en CommitmentReadIsm", "7/7 completo"],
        ["IAR-DD-04", "High", "Falta de control de acceso rompe el commit-reveal", "7/7 completo"],
        ["IAR-DD-05", "Medium", "Multicall atómico provoca DoS permanente de mensajes", "7/7 completo"],
    ],
    col_widths=[1.1, 1.0, 3.2, 1.0],
)
body(
    "En el fuzzing de este componente, la fase Medusa ejecutó 2,2 millones de llamadas y la optimización "
    "Echidna estimó un drenaje máximo de ~100 ETH, cuantificando el impacto económico del hallazgo. Cada "
    "uno de los cinco hallazgos cuenta con su prueba de concepto sobre fork.", space_after=8,
)
callout(
    "Lectura honesta del estado",
    "El sistema ha demostrado capacidad técnica para producir hallazgos de alta severidad con prueba. El "
    "trabajo pendiente de mayor valor para el negocio no es más tecnología, sino: (1) cerrar el ciclo hasta "
    "pagos confirmados, (2) acelerar el tiempo de envío para no perder hallazgos como duplicados, y (3) "
    "ampliar cobertura a dominios de mayor payout y menor competencia (ZK, restaking).",
    bg="FFF4E6", bar="E8821E",
)

# ============================================================================
# 13. MÉTRICAS Y POSICIONAMIENTO
# ============================================================================
heading("13. Métricas, economía y posicionamiento competitivo", 1)
body(
    "La única métrica que el sistema considera real es bugs aceptados / tiempo invertido. Toda la "
    "infraestructura es un acelerador, no un sustituto del pensamiento profundo. El siguiente cuadro "
    "recoge los objetivos operativos a 30 días definidos internamente."
)
make_table(
    ["Métrica", "Objetivo a 30 días"],
    [
        ["Tasa de acierto (pagados / enviados)", "20 %+"],
        ["Tasa de rechazo", "< 10 %"],
        ["Tasa de duplicados", "< 10 %"],
        ["Hallazgos derivados de invariantes", "3+"],
        ["Tiempo de envío para bounties abiertos", "< 4 horas"],
        ["Protocolos documentados en la base de conocimiento", "Cobertura completa"],
    ],
    col_widths=[3.8, 1.9],
)
heading("Posicionamiento competitivo", 2)
body(
    "El sistema se sitúa en el 20 % superior del sector en sofisticación de infraestructura. Los mejores "
    "cazadores individuales del mundo (que cobran de 500 a 2.000 USD/hora o ganan millones por bounty) NO "
    "automatizan: leen código en profundidad durante semanas. La estrategia ganadora documentada en el "
    "sector es la combinación humano + IA, que alcanza tasas de detección del orden del 94 %. El sistema "
    "está diseñado precisamente como ese acelerador para un experto, no como un reemplazo autónomo del juicio."
)

# ============================================================================
# 14. RIESGOS Y LEGAL
# ============================================================================
heading("14. Riesgos, límites y consideraciones legales", 1)
heading("Seguridad jurídica", 2)
body(
    "Es un punto crítico para la dirección y está resuelto por diseño. Todas las pruebas de concepto se "
    "ejecutan sobre un fork local: una copia del estado de la cadena leída en local, donde toda la "
    "ejecución ocurre en la máquina del equipo. Esto es plenamente legal. El sistema NUNCA ejecuta "
    "transacciones reales en mainnet o testnet, lo que equivaldría a robar fondos. Un PoC con fork local "
    "es suficiente para cualquier bug bounty."
)
heading("Riesgos operativos y mitigaciones", 2)
make_table(
    ["Riesgo", "Mitigación incorporada"],
    [
        ["Falsos positivos dañan la reputación", "Gates estrictos + RedTeam obligatorio + confirmación en fork"],
        ["Hallazgos perdidos como duplicados", "Protocolo de envío rápido (< 4 h) para bounties abiertos"],
        ["Cobertura desigual entre dominios", "Plan de poblar categorías vacías de alto valor (DEX, ZK, restaking)"],
        ["Exceso de construcción sobre caza", "Métrica única: bugs aceptados / tiempo; congelar tooling no esencial"],
        ["Dependencia de simulaciones imperfectas", "Fork obligatorio para todo DeFi antes de reportar"],
    ],
    col_widths=[2.6, 3.1],
)
callout(
    "La verdad incómoda",
    "Las herramientas son un acelerador, no un sustituto del pensamiento profundo. El camino más corto al "
    "valor no es más infraestructura, sino cazar bugs reales con la maquinaria que ya existe y cerrar el "
    "ciclo hasta el pago confirmado.",
)

# ============================================================================
# 15. HOJA DE RUTA Y CONCLUSIÓN
# ============================================================================
heading("15. Hoja de ruta y conclusión", 1)
make_table(
    ["Horizonte", "Foco principal"],
    [
        ["Inmediato", "Convertir hallazgos verificados en envíos y pagos; enviar lo pendiente"],
        ["Corto plazo", "Especialización en ZK (mayor payout, menor competencia); orquestador end-to-end"],
        ["Medio plazo", "Reputación en dominios de alto valor, presencia en contests, pipeline multi-cadena"],
        ["Continuo", "Feedback loop activo: cada outcome documentado mejora la detección"],
    ],
    col_widths=[1.4, 4.3],
)
body(
    "En síntesis, la dirección dispone de un sistema técnicamente maduro que industrializa la parte más "
    "costosa de la auditoría de seguridad Web3: generar hipótesis de ataque de calidad y verificarlas con "
    "pruebas ejecutables. Su disciplina de calidad —gates, RedTeam, confirmación en fork y reglas de rechazo "
    "aprendidas de pérdidas reales— está diseñada para proteger la reputación y maximizar la tasa de "
    "aceptación. El reto y la oportunidad de los próximos meses no son tecnológicos, sino de ejecución "
    "comercial: convertir capacidad demostrada en ingresos recurrentes, con foco en los dominios de mayor "
    "valor y menor competencia.", space_after=10,
)
callout(
    "Mensaje final para dirección",
    "Tenemos la maquinaria. La prioridad es usarla a pleno rendimiento sobre los objetivos correctos y "
    "cerrar el ciclo hasta el ingreso confirmado. La inversión marginal de mayor retorno es de proceso y "
    "foco, no de más construcción.",
    bg="E8F6F4", bar="0E7C86",
)

# ============================================================================
# ANEXO A — GLOSARIO
# ============================================================================
doc.add_page_break()
heading("Anexo A — Glosario de términos", 1)
glossary = [
    ("Bug bounty", "Programa de recompensa que paga a quien reporta de forma responsable vulnerabilidades en un protocolo."),
    ("Smart contract", "Programa que se ejecuta en una blockchain, gestiona fondos y es público e inmutable una vez desplegado."),
    ("Invariante", "Regla que el protocolo asume siempre verdadera. Si se rompe, suele haber un bug."),
    ("Fuzzing", "Técnica que bombardea el código con millones de entradas aleatorias buscando romper sus invariantes."),
    ("Fork (local)", "Copia del estado real de una blockchain, leída en local, sobre la que se prueba sin ejecutar transacciones reales."),
    ("PoC (prueba de concepto)", "Test ejecutable que demuestra el exploit y cuantifica la pérdida de fondos."),
    ("Hunter", "Agente de IA especializado en una familia de vulnerabilidades."),
    ("Gate", "Punto de control automático que impide avanzar si no existen las evidencias requeridas."),
    ("RedTeam", "Ejercicio adversario interno donde varios atacantes intentan refutar un hallazgo antes de reportarlo."),
    ("Reentrancy", "Vulnerabilidad en la que una llamada externa reentra al contrato con el estado a medio actualizar."),
    ("Oráculo", "Fuente externa de datos (típicamente precios) que un contrato consume; manipulable si está mal diseñado."),
    ("Flash loan", "Préstamo sin colateral que se toma y devuelve en la misma transacción; herramienta común de ataque."),
    ("TWAP", "Precio medio ponderado por tiempo; defensa frente a manipulación puntual de precio si la ventana es suficiente."),
    ("Duplicado", "Hallazgo válido pero ya reportado antes por otro; en plataformas con leaderboard aún puede dar puntos."),
    ("ZK", "Pruebas de conocimiento cero; dominio técnico de alto payout y menor competencia."),
]
for term, definition in glossary:
    p = doc.add_paragraph()
    p.paragraph_format.space_after = Pt(4)
    r = p.add_run(f"{term} — ")
    r.font.bold = True
    r.font.color.rgb = NAVY
    r.font.size = Pt(10.5)
    r2 = p.add_run(definition)
    r2.font.size = Pt(10.5)

# ----------------------------------------------------------------------------
out = "/home/user/web3bom/docs/Sistema-Bug-Bounty-Web3-Direccion.docx"
doc.save(out)
print("Documento generado:", out)
