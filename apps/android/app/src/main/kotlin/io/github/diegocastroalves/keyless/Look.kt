package io.github.diegocastroalves.keyless

import android.app.Activity
import android.content.Context
import android.content.res.ColorStateList
import android.content.res.Configuration
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.ColorDrawable
import android.graphics.drawable.Drawable
import android.graphics.drawable.GradientDrawable
import android.graphics.drawable.RippleDrawable
import android.graphics.fonts.Font
import android.graphics.fonts.FontFamily
import android.graphics.fonts.FontStyle
import android.text.TextUtils
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.ViewOutlineProvider
import android.widget.EditText
import android.widget.ImageButton
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView

/*
 * The desktop app's look on the phone (apps/desktop/src/styles.css and
 * components/ui): its colors in light and dark (res/values[-night]/colors.xml),
 * Inter, its Lucide icons (res/drawable/ic_*), and components of the same
 * shape: hairline cards, list rows with the item's icon, fields with the
 * label above the value, and its buttons, text fields and chips.
 */

/** Every screen: light or dark as Settings > Theme says, the system's otherwise. */
abstract class KeylessActivity : Activity() {
    override fun attachBaseContext(base: Context) {
        super.attachBaseContext(base)
        val night = when (base.getSharedPreferences("keyless", Context.MODE_PRIVATE).getString("theme", "system")) {
            "light" -> Configuration.UI_MODE_NIGHT_NO
            "dark" -> Configuration.UI_MODE_NIGHT_YES
            else -> return
        }
        val type = base.resources.configuration.uiMode and Configuration.UI_MODE_TYPE_MASK
        applyOverrideConfiguration(Configuration().apply { uiMode = type or night })
    }
}

val Context.isDark: Boolean
    get() = resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK == Configuration.UI_MODE_NIGHT_YES

fun Context.dpf(value: Float): Float = value * resources.displayMetrics.density

// ----- type ------------------------------------------------------------------------

private val faces = HashMap<Int, Typeface>()

/** Inter at `weight`: 400 regular, 500 medium, 600 semibold, 700 bold. */
fun Context.inter(weight: Int): Typeface = faces.getOrPut(weight) {
    try {
        val font = Font.Builder(resources, R.font.inter).setWeight(weight).setFontVariationSettings("'wght' $weight").build()
        Typeface.CustomFallbackBuilder(FontFamily.Builder(font).build())
            .setStyle(FontStyle(weight, FontStyle.FONT_SLANT_UPRIGHT))
            .setSystemFallback("sans-serif")
            .build()
    } catch (e: Exception) {
        Typeface.create(Typeface.SANS_SERIF, weight, false)
    }
}

fun TextView.weight(weight: Int): TextView {
    typeface = context.inter(weight)
    return this
}

// ----- shapes ----------------------------------------------------------------------

/** A rounded rectangle: `fill`, and a `stroke` line when given (colors, not ids). */
fun Context.shape(fill: Int, radius: Float, stroke: Int? = null, strokeWidth: Float = 1f): GradientDrawable =
    GradientDrawable().apply {
        cornerRadius = dpf(radius)
        setColor(fill)
        if (stroke != null) setStroke(dpf(strokeWidth).toInt().coerceAtLeast(1), stroke)
    }

/** The touch feedback over `content`, kept in `radius`. */
fun Context.pressable(content: Drawable?, radius: Float = 0f): RippleDrawable {
    val mask = if (radius > 0f || content == null) shape(Color.WHITE, radius) else null
    return RippleDrawable(ColorStateList.valueOf(getColor(R.color.press)), content, mask)
}

/** A hairline; add it with its own layout (a View that wraps its content fills the space left). */
fun Context.divider(): View = View(this).apply {
    setBackgroundColor(getColor(R.color.line))
    layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(1).coerceAtLeast(1))
}

// ----- icons -----------------------------------------------------------------------

fun Context.iconDrawable(res: Int, tint: Int): Drawable = getDrawable(res)!!.mutate().apply { setTint(tint) }

fun Context.icon(res: Int, tint: Int = getColor(R.color.muted), size: Int = 20): ImageView =
    ImageView(this).apply {
        setImageDrawable(iconDrawable(res, tint))
        layoutParams = LinearLayout.LayoutParams(dp(size), dp(size))
    }

/** An icon that acts (44 dp to touch), named for screen readers and long presses. */
fun Context.iconButton(res: Int, description: String, tint: Int = getColor(R.color.muted), onClick: () -> Unit): ImageButton =
    ImageButton(this).apply {
        setImageDrawable(iconDrawable(res, tint))
        contentDescription = description
        tooltipText = description
        background = pressable(null)
        scaleType = ImageView.ScaleType.CENTER
        val pad = dp(11)
        setPadding(pad, pad, pad, pad)
        layoutParams = LinearLayout.LayoutParams(dp(44), dp(44))
        setOnClickListener { onClick() }
    }

// ----- bars, cards and titles --------------------------------------------------------

/** A screen's top bar: Back (when `onBack`), the title, then `actions`. */
fun Context.topBar(title: CharSequence?, onBack: (() -> Unit)?, vararg actions: View): LinearLayout =
    LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        minimumHeight = dp(56)
        setPadding(dp(if (onBack == null) 16 else 4), dp(4), dp(4), dp(4))
        if (onBack != null) addView(iconButton(R.drawable.ic_back, getString(R.string.back), getColor(R.color.fg)) { onBack() })
        val name = TextView(context).apply {
            text = title ?: ""
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 20f)
            setTextColor(getColor(R.color.fg))
            weight(600)
            setSingleLine(true)
            ellipsize = TextUtils.TruncateAt.END
            setPadding(dp(if (onBack == null) 0 else 4), 0, dp(8), 0)
        }
        addView(name, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        for (action in actions) addView(action)
    }

/** A group of rows (an item's fields): a rounded surface over the screen, a hairline between rows from their text on. */
fun Context.card(): LinearLayout = LinearLayout(this).apply {
    orientation = LinearLayout.VERTICAL
    background = shape(getColor(R.color.panel), 16f)
    dividerDrawable = android.graphics.drawable.InsetDrawable(GradientDrawable().apply {
        setColor(getColor(R.color.line))
        setSize(0, dp(1).coerceAtLeast(1))
    }, dp(16), 0, 0, 0)
    showDividers = LinearLayout.SHOW_DIVIDER_MIDDLE
    // Rows' touch feedback stays inside the corners.
    outlineProvider = ViewOutlineProvider.BACKGROUND
    clipToOutline = true
}

/** A group's title, over it: semibold, as a list's heading. */
fun Context.sectionTitle(text: String): TextView = TextView(this).apply {
    this.text = text
    setTextSize(TypedValue.COMPLEX_UNIT_SP, 15f)
    setTextColor(getColor(R.color.fg))
    weight(600)
    setPadding(dp(4), 0, dp(4), 0)
}

// ----- an item's icon --------------------------------------------------------------

/** The desktop's avatar colors (Tailwind 600, cyan 700). */
private val AVATAR_COLORS = intArrayOf(0xFF0284C7.toInt(), 0xFF7C3AED.toInt(), 0xFF059669.toInt(), 0xFFE11D48.toInt(), 0xFFD97706.toInt(), 0xFF4F46E5.toInt(), 0xFF0D9488.toInt(), 0xFFC026D3.toInt(), 0xFFEA580C.toInt(), 0xFF0E7490.toInt())

/** The same color as the desktop for the same website or title. */
fun avatarColor(seed: String): Int {
    var hash = 0
    for (ch in seed) hash = hash * 31 + ch.code
    return AVATAR_COLORS[Math.floorMod(kotlin.math.abs(hash.toLong()), AVATAR_COLORS.size.toLong()).toInt()]
}

/** A category's icon and its tint: the 500 color under it, and the light and dark icon colors. */
private class Tint(val icon: Int, val base: Long, val light: Long, val dark: Long)

private val CATEGORY_LOOK = mapOf(
    "login" to Tint(R.drawable.ic_cat_login, 0xFF0EA5E9, 0xFF0284C7, 0xFF7DD3FC),
    "password" to Tint(R.drawable.ic_cat_password, 0xFF8B5CF6, 0xFF7C3AED, 0xFFC4B5FD),
    "secure_note" to Tint(R.drawable.ic_cat_secure_note, 0xFFF59E0B, 0xFFD97706, 0xFFFCD34D),
    "credit_card" to Tint(R.drawable.ic_cat_credit_card, 0xFF10B981, 0xFF059669, 0xFF6EE7B7),
    "identity" to Tint(R.drawable.ic_cat_identity, 0xFF6366F1, 0xFF4F46E5, 0xFFA5B4FC),
    "bank_account" to Tint(R.drawable.ic_cat_bank_account, 0xFF14B8A6, 0xFF0D9488, 0xFF5EEAD4),
    "api_credential" to Tint(R.drawable.ic_cat_api_credential, 0xFFD946EF, 0xFFC026D3, 0xFFF0ABFC),
    "database" to Tint(R.drawable.ic_cat_database, 0xFFF97316, 0xFFEA580C, 0xFFFDBA74),
    "server" to Tint(R.drawable.ic_cat_server, 0xFF64748B, 0xFF475569, 0xFFCBD5E1),
    "ssh_key" to Tint(R.drawable.ic_cat_ssh_key, 0xFF71717A, 0xFF3F3F46, 0xFFD4D4D8),
    "software_license" to Tint(R.drawable.ic_cat_software_license, 0xFFEAB308, 0xFFA16207, 0xFFFDE047),
    "wireless_router" to Tint(R.drawable.ic_cat_wireless_router, 0xFF06B6D4, 0xFF0891B2, 0xFF67E8F9),
    "email_account" to Tint(R.drawable.ic_cat_email_account, 0xFFF43F5E, 0xFFE11D48, 0xFFFDA4AF),
    "passport" to Tint(R.drawable.ic_cat_passport, 0xFF3B82F6, 0xFF2563EB, 0xFF93C5FD),
    "driver_license" to Tint(R.drawable.ic_cat_driver_license, 0xFF84CC16, 0xFF4D7C0F, 0xFFBEF264),
    "membership" to Tint(R.drawable.ic_cat_membership, 0xFFEC4899, 0xFFDB2777, 0xFFF9A8D4),
    "crypto_wallet" to Tint(R.drawable.ic_cat_crypto_wallet, 0xFFD97706, 0xFFB45309, 0xFFFCD34D),
    "medical_record" to Tint(R.drawable.ic_cat_medical_record, 0xFFEF4444, 0xFFDC2626, 0xFFFCA5A5),
    "document" to Tint(R.drawable.ic_cat_document, 0xFF78716C, 0xFF57534E, 0xFFD6D3D1),
    "other" to Tint(R.drawable.ic_cat_other, 0xFF6B7280, 0xFF4B5563, 0xFFD1D5DB),
)

/** A category's icon, tinted for this theme (16 to 24 dp, say). */
fun Context.categoryIcon(category: String, size: Int = 20): ImageView {
    val look = CATEGORY_LOOK[category] ?: CATEGORY_LOOK.getValue("other")
    return icon(look.icon, (if (isDark) look.dark else look.light).toInt(), size)
}

/**
 * An item's icon, as on the desktop: a login gets its website's icon, or a
 * letter on its website's color, anything else its category's icon on a
 * tint of its color.
 */
fun Context.itemIcon(category: String, title: String, url: String? = null, size: Int = 40): View {
    val radius = size / 4f
    val isLogin = category == "login" || category == "password"
    // The website's own icon, when Keyless has it (see SiteIcons).
    val site = if (isLogin && !url.isNullOrEmpty()) SiteIcons.of(hostOf(url)) else null
    if (site != null) {
        return ImageView(this).apply {
            setImageBitmap(site.bitmap)
            if (site.padded) {
                scaleType = ImageView.ScaleType.FIT_CENTER
                val pad = (size * 0.14f).toInt()
                setPadding(dp(pad), dp(pad), dp(pad), dp(pad))
                background = shape(Color.WHITE, radius)
            } else {
                scaleType = ImageView.ScaleType.CENTER_CROP
                background = shape(Color.TRANSPARENT, radius)
            }
            outlineProvider = ViewOutlineProvider.BACKGROUND
            clipToOutline = true
            layoutParams = LinearLayout.LayoutParams(dp(size), dp(size))
        }
    }
    if (isLogin && (!url.isNullOrEmpty() || title.isNotEmpty())) {
        val seed = if (!url.isNullOrEmpty()) hostOf(url) else title
        val letter = Regex("[\\p{L}\\p{N}]").find(title.ifEmpty { seed })?.value?.uppercase() ?: "?"
        return TextView(this).apply {
            text = letter
            gravity = Gravity.CENTER
            setTextColor(Color.WHITE)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, size * 0.42f)
            weight(600)
            background = shape(avatarColor(seed), radius)
            layoutParams = LinearLayout.LayoutParams(dp(size), dp(size))
        }
    }
    val look = CATEGORY_LOOK[category] ?: CATEGORY_LOOK.getValue("other")
    val base = look.base.toInt()
    return ImageView(this).apply {
        setImageDrawable(iconDrawable(look.icon, (if (isDark) look.dark else look.light).toInt()))
        scaleType = ImageView.ScaleType.CENTER_INSIDE
        val pad = (size * 0.27f).toInt()
        setPadding(dp(pad), dp(pad), dp(pad), dp(pad))
        background = shape(Color.argb(38, Color.red(base), Color.green(base), Color.blue(base)), radius)
        layoutParams = LinearLayout.LayoutParams(dp(size), dp(size))
    }
}

/** A website's host, as the desktop shows it ("github.com"). */
fun hostOf(url: String): String {
    val withScheme = if (url.contains("://")) url else "https://$url"
    return (android.net.Uri.parse(withScheme).host ?: url).removePrefix("www.")
}

// ----- rows ------------------------------------------------------------------------

/** A list row: the icon, the title over the subtitle, and something at the end. */
fun Context.listRow(icon: View?, title: CharSequence, subtitle: CharSequence?, trailing: View? = null): LinearLayout =
    LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        minimumHeight = dp(64)
        setPadding(dp(16), dp(10), dp(12), dp(10))
        background = pressable(null, 0f)
        if (icon != null) addView(icon)
        val texts = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(if (icon != null) dp(14) else 0, 0, dp(8), 0)
        }
        texts.addView(TextView(context).apply {
            text = title
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 16f)
            setTextColor(getColor(R.color.fg))
            weight(500)
            setSingleLine(true)
            ellipsize = TextUtils.TruncateAt.END
        })
        if (!subtitle.isNullOrEmpty()) {
            texts.addView(TextView(context).apply {
                text = subtitle
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 14f)
                setTextColor(getColor(R.color.muted))
                setSingleLine(true)
                ellipsize = TextUtils.TruncateAt.END
            })
        }
        addView(texts, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        if (trailing != null) addView(trailing)
    }

/** A field of an item: its name over its value, and the actions at the end. */
fun Context.fieldRow(name: String, value: View, vararg actions: View): LinearLayout =
    LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        minimumHeight = dp(60)
        setPadding(dp(16), dp(8), dp(4), dp(8))
        val texts = LinearLayout(context).apply { orientation = LinearLayout.VERTICAL }
        texts.addView(TextView(context).apply {
            text = name
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
            setTextColor(getColor(R.color.subtle))
            weight(500)
        })
        texts.addView(value, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = dp(2) })
        addView(texts, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        for (action in actions) addView(action)
    }

/** A row that opens something: an icon, a title (and a line under it), and a chevron. */
fun Context.navRow(iconRes: Int?, title: String, subtitle: String? = null, onClick: () -> Unit): LinearLayout {
    val start = iconRes?.let { icon(it, getColor(R.color.muted), 20) }
    return listRow(start, title, subtitle, icon(R.drawable.ic_chevron_right, getColor(R.color.subtle), 18)).apply {
        minimumHeight = dp(56)
        (getChildAt(if (start != null) 1 else 0) as LinearLayout).getChildAt(0).let { (it as TextView).textSize = 15f }
        setOnClickListener { onClick() }
    }
}

// ----- chips and search --------------------------------------------------------------

/** A filter: filled with the accent when chosen, outlined otherwise. */
fun Context.chip(text: String, selected: Boolean, onClick: () -> Unit): TextView = TextView(this).apply {
    this.text = text
    setTextSize(TypedValue.COMPLEX_UNIT_SP, 14f)
    weight(500)
    gravity = Gravity.CENTER
    minHeight = dp(34)
    setPadding(dp(14), 0, dp(14), 0)
    if (selected) {
        setTextColor(getColor(R.color.accent))
        background = pressable(shape(getColor(R.color.accent_soft), 17f), 17f)
    } else {
        setTextColor(getColor(R.color.muted))
        background = pressable(shape(getColor(R.color.panel), 17f, getColor(R.color.line)), 17f)
    }
    isSelected = selected
    setOnClickListener { onClick() }
}

/** The search box: a filled field with a magnifier. */
fun Context.searchField(hint: String): EditText = EditText(this).apply {
    this.hint = hint
    setSingleLine(true)
    setTextSize(TypedValue.COMPLEX_UNIT_SP, 15f)
    setTextColor(getColor(R.color.fg))
    setHintTextColor(getColor(R.color.subtle))
    background = shape(getColor(R.color.panel_3), 10f)
    minHeight = dp(44)
    setPadding(dp(12), dp(8), dp(12), dp(8))
    val glass = iconDrawable(R.drawable.ic_search, getColor(R.color.subtle)).apply { setBounds(0, 0, dp(18), dp(18)) }
    setCompoundDrawablesRelative(glass, null, null, null)
    compoundDrawablePadding = dp(8)
}

/** A screen's background, under its groups. */
fun View.onPanel(): View {
    setBackgroundColor(context.getColor(R.color.screen))
    return this
}

fun Context.colorDrawable(id: Int): ColorDrawable = ColorDrawable(getColor(id))

/** For a screen built as an Activity: the theme's colors on its window. */
fun Activity.panelWindow() {
    window.setBackgroundDrawable(colorDrawable(R.color.screen))
}

/** The top of the sign-in and unlock screens, as the desktop's lock screen: the app's icon, a title and a line. */
fun Context.brandHeader(title: String, line: String?): LinearLayout = LinearLayout(this).apply {
    orientation = LinearLayout.VERTICAL
    gravity = Gravity.CENTER_HORIZONTAL
    // Smaller on short screens, where the form under it needs the room.
    val short = resources.configuration.screenHeightDp < 720
    setPadding(0, dp(if (short) 4 else 24), 0, dp(8))
    val logo = dp(if (short) 52 else 72)
    addView(ImageView(context).apply { setImageDrawable(getDrawable(R.mipmap.ic_launcher)) }, LinearLayout.LayoutParams(logo, logo))
    addView(TextView(context).apply {
        text = title
        gravity = Gravity.CENTER
        setTextSize(TypedValue.COMPLEX_UNIT_SP, if (short) 21f else 24f)
        letterSpacing = -0.01f
        setTextColor(getColor(R.color.fg))
        weight(600)
    }, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = dp(if (short) 12 else 20) })
    if (!line.isNullOrEmpty()) {
        addView(TextView(context).apply {
            text = line
            gravity = Gravity.CENTER
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 14f)
            setTextColor(getColor(R.color.muted))
            setLineSpacing(0f, 1.2f)
        }, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = dp(6) })
    }
}

/** A quiet link under a form (the desktop's subtle text buttons), with an icon when given. */
fun Context.quietButton(text: String, iconRes: Int? = null, onClick: () -> Unit): android.widget.Button =
    android.widget.Button(this, null, android.R.attr.borderlessButtonStyle).apply {
        this.text = text
        isAllCaps = false
        stateListAnimator = null
        setTextSize(TypedValue.COMPLEX_UNIT_SP, 14f)
        setTextColor(getColor(R.color.muted))
        weight(500)
        minHeight = dp(40)
        minimumHeight = dp(40)
        background = pressable(null, 8f)
        if (iconRes != null) {
            setCompoundDrawablesRelative(iconDrawable(iconRes, getColor(R.color.muted)).apply { setBounds(0, 0, dp(16), dp(16)) }, null, null, null)
            compoundDrawablePadding = dp(6)
        }
        setOnClickListener { onClick() }
    }

/** Back, at the top of a page with a large title under it. */
fun LinearLayout.addBack(onBack: () -> Unit) {
    val back = context.iconButton(R.drawable.ic_back, context.getString(R.string.back), context.getColor(R.color.fg)) { onBack() }
    addView(back, LinearLayout.LayoutParams(context.dp(44), context.dp(44)).apply {
        // The arrow lines up with the title.
        marginStart = -context.dp(11)
        topMargin = -context.dp(8)
    })
}

/** Adds `view` centered across the column (links under a form). */
fun LinearLayout.addCentered(view: View, top: Int = 0) {
    addView(view, LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
        gravity = Gravity.CENTER_HORIZONTAL
        topMargin = context.dp(top)
    })
}

/** A password with its digits and symbols in their colors, as the desktop shows it. */
fun Context.passwordText(secret: String): CharSequence {
    val text = android.text.SpannableString(secret)
    secret.forEachIndexed { i, c ->
        val color = when {
            c.isDigit() -> R.color.digit
            !c.isLetter() -> R.color.symbol
            else -> return@forEachIndexed
        }
        text.setSpan(android.text.style.ForegroundColorSpan(getColor(color)), i, i + 1, android.text.Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
    }
    return text
}

// ----- the phone's own structure -----------------------------------------------------
//
// Screens on `screen`, groups of rows on `panel` over it without lines, a
// search pill and the account at the top, tabs at the bottom and the main
// action floating over the content: how phone apps are laid out, in the
// desktop's colors, font and icons.

/** A color family: the 500 shade under an icon, and the icon's color in light and dark. */
class Hue(val base: Long, val light: Long, val dark: Long)

object Hues {
    val amber = Hue(0xFFF59E0B, 0xFFD97706, 0xFFFCD34D)
    val cyan = Hue(0xFF06B6D4, 0xFF0891B2, 0xFF67E8F9)
    val green = Hue(0xFF10B981, 0xFF059669, 0xFF6EE7B7)
    val blue = Hue(0xFF3B82F6, 0xFF2563EB, 0xFF93C5FD)
    val violet = Hue(0xFF8B5CF6, 0xFF7C3AED, 0xFFC4B5FD)
    val slate = Hue(0xFF64748B, 0xFF475569, 0xFFCBD5E1)
    val rose = Hue(0xFFF43F5E, 0xFFE11D48, 0xFFFDA4AF)
    val indigo = Hue(0xFF6366F1, 0xFF4F46E5, 0xFFA5B4FC)
    val teal = Hue(0xFF14B8A6, 0xFF0D9488, 0xFF5EEAD4)
    val orange = Hue(0xFFF97316, 0xFFEA580C, 0xFFFDBA74)
    val red = Hue(0xFFEF4444, 0xFFDC2626, 0xFFFCA5A5)
}

/** `hue`'s icon color in this theme. */
fun Context.hueColor(hue: Hue): Int = (if (isDark) hue.dark else hue.light).toInt()

/** An icon on a round tint of its color: the start of a row, or of a group's title. */
fun Context.roundIcon(res: Int, hue: Hue, size: Int = 40): ImageView = ImageView(this).apply {
    val base = hue.base.toInt()
    setImageDrawable(iconDrawable(res, hueColor(hue)))
    scaleType = ImageView.ScaleType.CENTER_INSIDE
    val pad = (size * 0.27f).toInt()
    setPadding(dp(pad), dp(pad), dp(pad), dp(pad))
    background = GradientDrawable().apply {
        shape = GradientDrawable.OVAL
        setColor(Color.argb(if (isDark) 46 else 36, Color.red(base), Color.green(base), Color.blue(base)))
    }
    layoutParams = LinearLayout.LayoutParams(dp(size), dp(size))
}

/** Rows that belong together, on a rounded surface over the screen: no lines around or between them. */
fun Context.group(): LinearLayout = LinearLayout(this).apply {
    orientation = LinearLayout.VERTICAL
    background = shape(getColor(R.color.panel), 16f)
    setPadding(0, dp(6), 0, dp(6))
    outlineProvider = ViewOutlineProvider.BACKGROUND
    clipToOutline = true
}

/** A group's title row: its icon, the name, and a chevron that folds it (when `open` is given). */
fun Context.groupHeader(icon: View?, title: String, open: Boolean? = null, onToggle: (() -> Unit)? = null, vararg actions: View): LinearLayout =
    LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        minimumHeight = dp(60)
        setPadding(dp(16), dp(8), dp(8), dp(8))
        if (icon != null) addView(icon)
        addView(TextView(context).apply {
            text = title
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 17f)
            setTextColor(getColor(R.color.fg))
            weight(600)
            setSingleLine(true)
            ellipsize = TextUtils.TruncateAt.END
            setPadding(if (icon != null) dp(14) else 0, 0, dp(8), 0)
        }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        for (action in actions) addView(action)
        if (open != null && onToggle != null) {
            val chevron = iconButton(if (open) R.drawable.ic_chevron_up else R.drawable.ic_chevron_down, getString(if (open) R.string.fold else R.string.unfold), accent()) { onToggle() }
            addView(chevron)
            background = pressable(null, 0f)
            setOnClickListener { onToggle() }
        }
    }

/** A section's name over the groups that follow it (bold, as a list's heading). */
fun Context.heading(text: String, trailing: View? = null): LinearLayout = LinearLayout(this).apply {
    orientation = LinearLayout.HORIZONTAL
    gravity = Gravity.CENTER_VERTICAL
    minimumHeight = dp(44)
    setPadding(dp(4), 0, 0, 0)
    addView(TextView(context).apply {
        this.text = text
        setTextSize(TypedValue.COMPLEX_UNIT_SP, 16f)
        setTextColor(getColor(R.color.fg))
        weight(600)
    }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
    if (trailing != null) addView(trailing)
}

/** A row of a group that opens something: a round icon, a title (and a line under it), and what is at the end. */
fun Context.groupRow(icon: View?, title: CharSequence, subtitle: CharSequence? = null, trailing: View? = null, onClick: (() -> Unit)? = null): LinearLayout =
    listRow(icon, title, subtitle, trailing).apply {
        minimumHeight = dp(if (subtitle.isNullOrEmpty()) 56 else 64)
        if (onClick != null) setOnClickListener { onClick() } else background = null
    }

/** Lets a row's subtitle (from listRow or groupRow) take up to `lines` lines. */
fun LinearLayout.wrapSubtitle(lines: Int = 3): LinearLayout = apply {
    val texts = (0 until childCount).map { getChildAt(it) }.firstOrNull { it is LinearLayout } as? LinearLayout ?: return@apply
    (texts.getChildAt(1) as? TextView)?.apply {
        setSingleLine(false)
        maxLines = lines
    }
}

/** A count at the end of a row ("12"). */
fun Context.countText(count: Int): TextView = TextView(this).apply {
    text = count.toString()
    setTextSize(TypedValue.COMPLEX_UNIT_SP, 14f)
    setTextColor(getColor(R.color.subtle))
    setPadding(dp(8), 0, dp(4), 0)
}

/** The search at the top of the main tabs: a pill that opens the search screen. */
fun Context.searchPill(hint: String, onClick: () -> Unit): LinearLayout = LinearLayout(this).apply {
    orientation = LinearLayout.HORIZONTAL
    gravity = Gravity.CENTER_VERTICAL
    minimumHeight = dp(52)
    setPadding(dp(18), 0, dp(18), 0)
    background = pressable(shape(getColor(R.color.search_pill), 26f), 26f)
    if (!isDark) elevation = dpf(1.5f)
    addView(icon(R.drawable.ic_search, getColor(R.color.muted), 20))
    addView(TextView(context).apply {
        text = hint
        setTextSize(TypedValue.COMPLEX_UNIT_SP, 16f)
        setTextColor(getColor(R.color.muted))
        setSingleLine(true)
        ellipsize = TextUtils.TruncateAt.END
        setPadding(dp(12), 0, 0, 0)
    }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
    contentDescription = hint
    isFocusable = true
    setOnClickListener { onClick() }
}

/** The account's letter on its color (the email's, as the desktop's avatars): opens the account menu; named `description`. */
fun Context.accountButton(email: String, description: String, onClick: (() -> Unit)?): android.widget.FrameLayout = android.widget.FrameLayout(this).apply {
    background = GradientDrawable().apply {
        shape = GradientDrawable.OVAL
        setColor(avatarColor(email))
    }
    foreground = if (onClick != null) pressable(null, 20f) else null
    contentDescription = description
    addView(TextView(context).apply {
        text = Regex("[\\p{L}\\p{N}]").find(email)?.value?.uppercase() ?: "?"
        gravity = Gravity.CENTER
        setTextColor(Color.WHITE)
        setTextSize(TypedValue.COMPLEX_UNIT_SP, 17f)
        weight(600)
        importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
    }, android.widget.FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT))
    layoutParams = LinearLayout.LayoutParams(dp(40), dp(40))
    if (onClick != null) {
        tooltipText = description
        setOnClickListener { onClick() }
    } else {
        importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
    }
}

/** A tab of the bottom bar: its id, icon and name. */
class Tab(val id: String, val icon: Int, val name: String)

/** The bottom bar: each tab's icon (on a pill when it is the one shown) over its name. */
fun Context.bottomBar(tabs: List<Tab>, selected: String, onSelect: (String) -> Unit): LinearLayout = LinearLayout(this).apply {
    orientation = LinearLayout.HORIZONTAL
    setBackgroundColor(getColor(R.color.nav_bar))
    elevation = dpf(8f)
    outlineProvider = ViewOutlineProvider.BOUNDS
    setPadding(0, dp(10), 0, dp(12))
    for (tab in tabs) {
        val chosen = tab.id == selected
        val cell = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
            contentDescription = tab.name
            isSelected = chosen
            setOnClickListener { onSelect(tab.id) }
        }
        val pill = ImageView(context).apply {
            setImageDrawable(iconDrawable(tab.icon, getColor(if (chosen) R.color.accent else R.color.muted)))
            scaleType = ImageView.ScaleType.CENTER
            background = if (chosen) shape(getColor(R.color.accent_soft), 16f) else pressable(null, 16f)
            importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
        }
        cell.addView(pill, LinearLayout.LayoutParams(dp(64), dp(32)))
        cell.addView(TextView(context).apply {
            text = tab.name
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
            setTextColor(getColor(if (chosen) R.color.fg else R.color.muted))
            weight(if (chosen) 600 else 500)
            gravity = Gravity.CENTER
            setSingleLine(true)
            importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
        }, LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = dp(4) })
        addView(cell, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
    }
}

/** The main action, floating at the bottom end: a plus and its name, folded to the plus while the content scrolls. */
class Fab(context: Context, text: String, onClick: () -> Unit) : LinearLayout(context) {
    private val name: TextView

    init {
        orientation = HORIZONTAL
        gravity = Gravity.CENTER
        minimumHeight = context.dp(56)
        minimumWidth = context.dp(56)
        setPadding(context.dp(16), 0, context.dp(16), 0)
        background = context.pressable(context.shape(context.getColor(R.color.accent), 16f), 16f)
        elevation = context.dpf(6f)
        contentDescription = text
        addView(context.icon(R.drawable.ic_plus, context.getColor(R.color.accent_fg), 24))
        name = TextView(context).apply {
            this.text = text
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 16f)
            setTextColor(context.getColor(R.color.accent_fg))
            weight(600)
            setPadding(context.dp(10), 0, context.dp(4), 0)
            importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
        }
        addView(name)
        setOnClickListener { onClick() }
    }

    /** Only the plus (while scrolling down), or the plus and the name. */
    fun fold(folded: Boolean) {
        name.visibility = if (folded) View.GONE else View.VISIBLE
    }
}

/** A category to start a new item with: its icon, a plus, and its name under them. */
fun Context.categoryTile(category: String, name: String, onClick: () -> Unit): LinearLayout = LinearLayout(this).apply {
    orientation = LinearLayout.VERTICAL
    minimumHeight = dp(108)
    setPadding(dp(16), dp(14), dp(12), dp(14))
    background = pressable(shape(getColor(R.color.panel), 16f), 16f)
    contentDescription = name
    val top = LinearLayout(context).apply {
        orientation = LinearLayout.HORIZONTAL
        gravity = Gravity.TOP
    }
    top.addView(itemIcon(category, "", null, 40))
    top.addView(View(context), LinearLayout.LayoutParams(0, 1, 1f))
    top.addView(icon(R.drawable.ic_plus, getColor(R.color.muted), 20))
    addView(top)
    addView(TextView(context).apply {
        text = name
        setTextSize(TypedValue.COMPLEX_UNIT_SP, 15f)
        setTextColor(getColor(R.color.fg))
        weight(500)
        maxLines = 2
        ellipsize = TextUtils.TruncateAt.END
        importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
    }, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = dp(14) })
    setOnClickListener { onClick() }
}

/** A small rounded tag at the end of a row or title ("2 steps left"). */
fun Context.badge(text: String): TextView = TextView(this).apply {
    this.text = text
    setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
    setTextColor(getColor(R.color.accent_fg))
    weight(600)
    setPadding(dp(10), dp(4), dp(10), dp(4))
    background = shape(getColor(R.color.accent), 12f)
}
