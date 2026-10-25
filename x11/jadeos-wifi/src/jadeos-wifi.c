/* See LICENSE file for copyright and license details. */
/* jadeos-wifi: tray applet that lists and joins Wi-Fi networks with iwd. */
#include <sys/types.h>

#include <netinet/in.h>

#include <arpa/inet.h>
#include <err.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gtk/gtk.h>

#define IWD		"net.connman.iwd"
#define IWD_PATH	"/net/connman/iwd"
#define ADAPTER		IWD ".Adapter"
#define DEVICE		IWD ".Device"
#define STATION		IWD ".Station"
#define NETWORK		IWD ".Network"
#define KNOWN		IWD ".KnownNetwork"
#define DIAGNOSTIC	IWD ".StationDiagnostic"
#define CANCELED	IWD ".Agent.Error.Canceled"
#define AGENT_PATH	"/org/jadeos/wifi/agent"
#define REPORT		"jadeos-network-report.txt"
#define MENU_MAX	8
#define LEN(a)		(sizeof(a) / sizeof((a)[0]))

enum { SECRET_PSK, SECRET_KEY, SECRET_USER, SECRET_PASSWORD };
enum { RESPONSE_SAVE = 1 };
enum { WIFI_NOIWD, WIFI_NOADAPTER, WIFI_DISABLED, WIFI_STATES };

struct network {
	char	*name;
	char	*path;
	char	*type;
	int	 connected;
	int	 known;
	int	 signal;
};

struct secret {
	GDBusMethodInvocation	*invocation;
	GtkWidget		*connect;
	GtkWidget		*password;
	GtkWidget		*user;
	size_t			 max;
	size_t			 min;
};

static GDBusProxy	*proxy(const char *, const char *);
static char		*propstr(const char *, const char *, const char *);
static int		 propflag(const char *, const char *, const char *);
static GList		*paths(const char *);
static const char	*owner(void);
static void		 message(GtkMessageType, const char *, const char *);
static const char	*explain(GError *);
static void		 finished(GObject *, GAsyncResult *, gpointer);
static void		 call(const char *, const char *, const char *,
			    GVariant *, const char *);
static char		*readsys(const char *, const char *);
static char		*ipv4(const char *);
static char		*hwaddr(const char *);
static char		*gateway(const char *);
static char		*dns(const char *);
static GList		*wired(void);
static char		*wiredip(const char *);
static int		 hardblocked(void);
static void		 netfree(gpointer);
static gint		 connectedfirst(gconstpointer, gconstpointer);
static GList		*networks(const char *);
static int		 percent(int);
static char		*sigicon(int, int);
static const char	*security(const char *);
static void		 secretcheck(GtkWidget *, struct secret *);
static void		 secretshow(GtkToggleButton *, struct secret *);
static void		 answercancel(struct secret *, const char *);
static void		 answerpassword(struct secret *, const char *);
static void		 answeruser(struct secret *, const char *);
static void		 secretanswer(GtkDialog *, int, struct secret *);
static void		 ask(GDBusMethodInvocation *, GVariant *, int);
static void		 cancel(GDBusMethodInvocation *, GVariant *, int);
static void		 release(GDBusMethodInvocation *, GVariant *, int);
static void		 agentcall(GDBusConnection *, const char *,
			    const char *, const char *, const char *,
			    GVariant *, GDBusMethodInvocation *, gpointer);
static void		 registeragent(void);
static void		 wifistatus(char **, char **);
static void		 wiredstatus(char **, char **);
static void		 update(void);
static GtkWidget	*menuitem(const char *, const char *, int);
static void		 append(GtkWidget *, GtkWidget *);
static void		 header(GtkWidget *, const char *);
static GtkWidget	*action(GtkWidget *, const char *, GCallback,
			    const char *, int);
static void		 connectnet(GtkMenuItem *, const char *);
static void		 disconnectst(GtkMenuItem *, const char *);
static void		 forget(GtkMenuItem *, const char *);
static void		 power(GtkCheckMenuItem *, gpointer);
static void		 hiddenanswer(GtkDialog *, int, GtkWidget *);
static void		 hidden(GtkMenuItem *, const char *);
static void		 row(GtkWidget *, int *, const char *, const char *);
static void		 heading(GtkWidget *, int *, const char *);
static void		 addresses(GtkWidget *, int *, const char *);
static void		 wifiinfo(GtkWidget *, int *, const char *);
static void		 info(GtkMenuItem *, gpointer);
static void		 diagnosticsanswer(GtkDialog *, int, GtkTextBuffer *);
static void		 diagnostics(GtkMenuItem *, gpointer);
static void		 addnetwork(GtkWidget *, struct network *,
			    const char *);
static void		 stationsection(const char *);
static int		 wiredsection(void);
static int		 wifisection(GList *, GList *, int *);
static void		 knownsection(void);
static void		 build(void);
static void		 scan(void);
static void		 popup(guint, guint32);
static void		 popupicon(guint, guint32);
static void		 popuppointer(guint, guint32);
static void		 closed(gpointer);
static void		 clicked(gpointer);
static void		 rightclicked(GtkStatusIcon *, guint, guint, gpointer);
static gboolean		 refresh(gpointer);
static void		 changed(gpointer);
static void		 ownerchanged(gpointer);
static gboolean		 tick(gpointer);
static void		 startup(GApplication *, gpointer);
static void		 activate(GApplication *, gpointer);
static int		 commandline(GApplication *, GApplicationCommandLine *,
			    gpointer);
static void		 freepath(gpointer, GClosure *);

static const char agentxml[] =
    "<node><interface name='" IWD ".Agent'>"
    "<method name='Release'/>"
    "<method name='RequestPassphrase'>"
    "<arg type='o' direction='in'/><arg type='s' direction='out'/></method>"
    "<method name='RequestPrivateKeyPassphrase'>"
    "<arg type='o' direction='in'/><arg type='s' direction='out'/></method>"
    "<method name='RequestUserNameAndPassword'>"
    "<arg type='o' direction='in'/><arg type='s' direction='out'/>"
    "<arg type='s' direction='out'/></method>"
    "<method name='RequestUserPassword'>"
    "<arg type='o' direction='in'/><arg type='s' direction='in'/>"
    "<arg type='s' direction='out'/></method>"
    "<method name='Cancel'><arg type='s' direction='in'/></method>"
    "</interface></node>";

static const struct {
	const char	*name;
	void		(*handle)(GDBusMethodInvocation *, GVariant *, int);
	int		 kind;
} methods[] = {
	{ "RequestPassphrase", ask, SECRET_PSK },
	{ "RequestPrivateKeyPassphrase", ask, SECRET_KEY },
	{ "RequestUserNameAndPassword", ask, SECRET_USER },
	{ "RequestUserPassword", ask, SECRET_PASSWORD },
	{ "Cancel", cancel, 0 },
	{ "Release", release, 0 },
};

static const struct {
	const char	*text;
	const char	*label;
	size_t		 max;
	size_t		 min;
	int		 user;
} kinds[] = {
	[SECRET_PSK] = { "Passwords or encryption keys are required to access",
	    "_Password:", 64, 8, 0 },
	[SECRET_KEY] = { "A private key passphrase is required to access",
	    "_Passphrase:", 1024, 1, 0 },
	[SECRET_USER] = { "A user name and password are required to access",
	    "_Password:", 1024, 1, 1 },
	[SECRET_PASSWORD] = { "A password is required to access",
	    "_Password:", 1024, 1, 0 },
};

static const struct {
	const char	*name;
	const char	*text;
} errors[] = {
	{ IWD ".Aborted", NULL },
	{ CANCELED, NULL },
	{ IWD ".Failed",
	    "The connection failed. Check the password and try again." },
	{ IWD ".NotFound", "The network is not in range any more." },
	{ IWD ".NotSupported", "This kind of network is not supported." },
	{ IWD ".NoAgent", "No password agent is registered; "
	    "restart jadeos-wifi." },
};

static const struct {
	const char	*level;
	int		 min;
} levels[] = {
	{ "100", 81 }, { "75", 56 }, { "50", 31 }, { "25", 6 }, { "00", 0 },
};

static const struct {
	const char	*type;
	const char	*name;
} securities[] = {
	{ "psk", "WPA Personal" },
	{ "8021x", "WPA Enterprise" },
	{ "open", "None (open network)" },
};

static const struct {
	const char	*key;
	const char	*label;
	const char	*format;
	unsigned int	 divisor;
} diagrows[] = {
	{ "Security", "Security", NULL, 1 },
	{ "Frequency", "Frequency", "%u MHz", 1 },
	{ "RxMode", "Standard", NULL, 1 },
	{ "TxBitrate", "Transmit rate", "%u Mbit/s", 10 },
};

static const struct {
	const char	*label;
	char		*(*get)(const char *);
} addrrows[] = {
	{ "Interface", g_strdup },
	{ "Hardware address", hwaddr },
	{ "IPv4 address", ipv4 },
	{ "Default route", gateway },
	{ "DNS servers", dns },
};

static const char *events[] = {
	"object-added", "object-removed", "interface-added",
	"interface-removed", "interface-proxy-properties-changed",
};

static const char *powered[] = { ADAPTER, DEVICE };

static void (*const answers[])(struct secret *, const char *) = {
	answercancel, answerpassword, answeruser,
};

static void (*const placements[])(guint, guint32) = {
	popupicon, popuppointer,
};

static const struct {
	GtkMessageType	 type;
	const char	*title;
} saved[] = {
	{ GTK_MESSAGE_ERROR, "Could not save the report" },
	{ GTK_MESSAGE_INFO, "Network report saved" },
};

static const char *wifinotes[] = {
	[WIFI_NOIWD] = "Wi-Fi service (iwd) is not running",
	[WIFI_NOADAPTER] =
	    "No Wi-Fi adapter found (no driver for it, or it needs firmware)",
	[WIFI_DISABLED] = "Wi-Fi is disabled",
};

static GDBusConnection		*bus;
static GDBusObjectManager	*manager;
static GtkStatusIcon		*tray;
static GtkWidget		*menu;
static GSList			*secrets;
static char			*agentowner;
static guint			 pending;
static int			 started;
static int			 openmenu;

static GDBusProxy *
proxy(const char *path, const char *iface)
{
	if (manager == NULL || path == NULL ||
	    !g_variant_is_object_path(path) || strcmp(path, "/") == 0)
		return NULL;
	return G_DBUS_PROXY(g_dbus_object_manager_get_interface(manager,
	    path, iface));
}

static char *
propstr(const char *path, const char *iface, const char *name)
{
	GDBusProxy *p;
	GVariant *v;
	char *s;

	s = NULL;
	v = NULL;
	if ((p = proxy(path, iface)) != NULL)
		v = g_dbus_proxy_get_cached_property(p, name);
	if (v != NULL && strchr("so", g_variant_classify(v)) != NULL)
		s = g_variant_dup_string(v, NULL);
	g_clear_pointer(&v, g_variant_unref);
	g_clear_object(&p);
	return s;
}

static int
propflag(const char *path, const char *iface, const char *name)
{
	GDBusProxy *p;
	GVariant *v;
	int flag;

	flag = 0;
	v = NULL;
	if ((p = proxy(path, iface)) != NULL)
		v = g_dbus_proxy_get_cached_property(p, name);
	if (v != NULL && g_variant_classify(v) == G_VARIANT_CLASS_BOOLEAN)
		flag = g_variant_get_boolean(v);
	g_clear_pointer(&v, g_variant_unref);
	g_clear_object(&p);
	return flag;
}

static GList *
paths(const char *iface)
{
	GDBusInterface *i;
	GList *objects, *l, *list;

	list = NULL;
	objects = NULL;
	if (manager != NULL)
		objects = g_dbus_object_manager_get_objects(manager);
	for (l = objects; l != NULL; l = l->next) {
		if ((i = g_dbus_object_get_interface(l->data, iface)) == NULL)
			continue;
		list = g_list_prepend(list,
		    g_strdup(g_dbus_object_get_object_path(l->data)));
		g_object_unref(i);
	}
	g_list_free_full(objects, g_object_unref);
	return g_list_sort(list, (GCompareFunc)strcmp);
}

static const char *
owner(void)
{
	static char *name;

	g_free(name);
	name = NULL;
	if (manager != NULL)
		name = g_dbus_object_manager_client_get_name_owner(
		    G_DBUS_OBJECT_MANAGER_CLIENT(manager));
	return name;
}

static void
message(GtkMessageType type, const char *title, const char *text)
{
	GtkWidget *d;

	d = gtk_message_dialog_new(NULL, 0, type, GTK_BUTTONS_CLOSE, "%s",
	    title);
	gtk_message_dialog_format_secondary_text(GTK_MESSAGE_DIALOG(d), "%s",
	    text);
	gtk_window_set_title(GTK_WINDOW(d), "Wi-Fi");
	gtk_window_set_icon_name(GTK_WINDOW(d), "network-wireless");
	gtk_window_set_position(GTK_WINDOW(d), GTK_WIN_POS_CENTER);
	gtk_window_set_keep_above(GTK_WINDOW(d), TRUE);
	g_signal_connect(d, "response", G_CALLBACK(gtk_widget_destroy), NULL);
	gtk_widget_show(d);
}

static const char *
explain(GError *error)
{
	const char *text;
	char *name;
	size_t i;

	name = g_dbus_error_get_remote_error(error);
	g_dbus_error_strip_remote_error(error);
	text = error->message;
	for (i = 0; name != NULL && i < LEN(errors); i++)
		if (strcmp(name, errors[i].name) == 0)
			text = errors[i].text;
	g_free(name);
	return text;
}

static void
finished(GObject *source, GAsyncResult *result, gpointer title)
{
	GError *error;
	GVariant *v;
	const char *text;

	error = NULL;
	v = g_dbus_connection_call_finish(G_DBUS_CONNECTION(source), result,
	    &error);
	g_clear_pointer(&v, g_variant_unref);
	if (error != NULL && (text = explain(error)) != NULL)
		message(GTK_MESSAGE_ERROR, title, text);
	g_clear_error(&error);
	g_free(title);
}

static void
call(const char *path, const char *iface, const char *method, GVariant *args,
    const char *title)
{
	g_dbus_connection_call(bus, IWD, path, iface, method, args, NULL,
	    G_DBUS_CALL_FLAGS_NONE, G_MAXINT, NULL, finished, g_strdup(title));
}

static char *
readsys(const char *format, const char *name)
{
	char *path, *text;

	text = NULL;
	path = g_strdup_printf(format, name);
	if (g_file_get_contents(path, &text, NULL, NULL))
		g_strstrip(text);
	g_free(path);
	return text;
}

static char *
ipv4(const char *ifname)
{
	struct ifaddrs *list, *a;
	struct sockaddr_in *sin;
	char buf[INET_ADDRSTRLEN], *found;

	found = NULL;
	if (ifname == NULL || getifaddrs(&list) < 0)
		return NULL;
	for (a = list; a != NULL && found == NULL; a = a->ifa_next) {
		if (a->ifa_addr == NULL || a->ifa_addr->sa_family != AF_INET ||
		    strcmp(a->ifa_name, ifname) != 0)
			continue;
		sin = (struct sockaddr_in *)a->ifa_addr;
		if (inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf)))
			found = g_strdup(buf);
	}
	freeifaddrs(list);
	return found;
}

static char *
hwaddr(const char *ifname)
{
	return readsys("/sys/class/net/%s/address", ifname);
}

static char *
gateway(const char *ifname)
{
	struct in_addr a;
	unsigned int dest, gw;
	char name[17], **lines, *text, *found;
	int i;

	found = NULL;
	if (!g_file_get_contents("/proc/net/route", &text, NULL, NULL))
		return NULL;
	lines = g_strsplit(text, "\n", -1);
	for (i = 1; lines[i] != NULL && found == NULL; i++) {
		if (sscanf(lines[i], "%16s %x %x", name, &dest, &gw) != 3 ||
		    dest != 0 || g_strcmp0(name, ifname) != 0)
			continue;
		a.s_addr = gw;
		found = g_strdup(inet_ntoa(a));
	}
	g_strfreev(lines);
	g_free(text);
	return found;
}

static char *
dns(const char *ifname)
{
	GString *out;
	char **lines, *text;
	int i;

	(void)ifname;
	text = NULL;
	out = g_string_new(NULL);
	g_file_get_contents("/etc/resolv.conf", &text, NULL, NULL);
	lines = g_strsplit(text != NULL ? text : "", "\n", -1);
	for (i = 0; lines[i] != NULL; i++) {
		if (!g_str_has_prefix(lines[i], "nameserver "))
			continue;
		g_string_append_printf(out, "%s%s", out->len > 0 ? ", " : "",
		    g_strstrip(lines[i] + 11));
	}
	g_strfreev(lines);
	g_free(text);
	return g_string_free(out, out->len == 0);
}

static GList *
wired(void)
{
	GDir *dir;
	GList *list;
	const char *name;
	char *dev, *wifi;

	list = NULL;
	if ((dir = g_dir_open("/sys/class/net", 0, NULL)) == NULL)
		return NULL;
	while ((name = g_dir_read_name(dir)) != NULL) {
		dev = g_strdup_printf("/sys/class/net/%s/device", name);
		wifi = g_strdup_printf("/sys/class/net/%s/wireless", name);
		if (g_file_test(dev, G_FILE_TEST_EXISTS) &&
		    !g_file_test(wifi, G_FILE_TEST_EXISTS))
			list = g_list_prepend(list, g_strdup(name));
		g_free(dev);
		g_free(wifi);
	}
	g_dir_close(dir);
	return g_list_sort(list, (GCompareFunc)strcmp);
}

static char *
wiredip(const char *ifname)
{
	char *carrier, *ip;

	ip = NULL;
	carrier = readsys("/sys/class/net/%s/carrier", ifname);
	if (g_strcmp0(carrier, "1") == 0)
		ip = ipv4(ifname);
	g_free(carrier);
	return ip;
}

static int
hardblocked(void)
{
	GDir *dir;
	const char *name;
	char *type, *hard;
	int blocked;

	blocked = 0;
	if ((dir = g_dir_open("/sys/class/rfkill", 0, NULL)) == NULL)
		return 0;
	while ((name = g_dir_read_name(dir)) != NULL) {
		type = readsys("/sys/class/rfkill/%s/type", name);
		hard = readsys("/sys/class/rfkill/%s/hard", name);
		blocked |= g_strcmp0(type, "wlan") == 0 &&
		    g_strcmp0(hard, "1") == 0;
		g_free(type);
		g_free(hard);
	}
	g_dir_close(dir);
	return blocked;
}

static void
netfree(gpointer data)
{
	struct network *n;

	n = data;
	g_free(n->name);
	g_free(n->path);
	g_free(n->type);
	g_free(n);
}

static gint
connectedfirst(gconstpointer a, gconstpointer b)
{
	const struct network *x, *y;

	x = a;
	y = b;
	return y->connected - x->connected;
}

static GList *
networks(const char *station)
{
	struct network *n;
	GVariantIter *iter;
	GVariant *reply;
	GList *list;
	const char *path;
	char *known;
	gint16 signal;

	list = NULL;
	reply = g_dbus_connection_call_sync(bus, IWD, station, STATION,
	    "GetOrderedNetworks", NULL, G_VARIANT_TYPE("(a(on))"),
	    G_DBUS_CALL_FLAGS_NONE, 3000, NULL, NULL);
	if (reply == NULL)
		return NULL;
	g_variant_get(reply, "(a(on))", &iter);
	while (g_variant_iter_next(iter, "(&on)", &path, &signal)) {
		n = g_new0(struct network, 1);
		n->path = g_strdup(path);
		n->name = propstr(path, NETWORK, "Name");
		n->type = propstr(path, NETWORK, "Type");
		n->connected = propflag(path, NETWORK, "Connected");
		known = propstr(path, NETWORK, "KnownNetwork");
		n->known = known != NULL;
		n->signal = signal / 100;
		g_free(known);
		list = g_list_append(list, n);
	}
	g_variant_iter_free(iter);
	g_variant_unref(reply);
	return g_list_sort(list, connectedfirst);
}

static int
percent(int dbm)
{
	return CLAMP(2 * (dbm + 100), 0, 100);
}

static char *
sigicon(int dbm, int secure)
{
	size_t i;
	int p;

	p = percent(dbm);
	for (i = 0; p < levels[i].min; i++)
		continue;
	return g_strdup_printf("nm-signal-%s%s", levels[i].level,
	    secure ? "-secure" : "");
}

static const char *
security(const char *type)
{
	size_t i;

	for (i = 0; i < LEN(securities); i++)
		if (g_strcmp0(type, securities[i].type) == 0)
			return securities[i].name;
	return type;
}

static void
secretcheck(GtkWidget *w, struct secret *s)
{
	size_t n;
	int ok;

	(void)w;
	n = strlen(gtk_entry_get_text(GTK_ENTRY(s->password)));
	ok = n >= s->min && n <= s->max && (s->user == NULL ||
	    *gtk_entry_get_text(GTK_ENTRY(s->user)) != '\0');
	gtk_widget_set_sensitive(s->connect, ok);
}

static void
secretshow(GtkToggleButton *button, struct secret *s)
{
	gtk_entry_set_visibility(GTK_ENTRY(s->password),
	    gtk_toggle_button_get_active(button));
}

static void
answercancel(struct secret *s, const char *pass)
{
	(void)pass;
	g_dbus_method_invocation_return_dbus_error(s->invocation, CANCELED,
	    "Canceled by the user");
}

static void
answerpassword(struct secret *s, const char *pass)
{
	g_dbus_method_invocation_return_value(s->invocation,
	    g_variant_new("(s)", pass));
}

static void
answeruser(struct secret *s, const char *pass)
{
	g_dbus_method_invocation_return_value(s->invocation,
	    g_variant_new("(ss)", gtk_entry_get_text(GTK_ENTRY(s->user)),
	    pass));
}

static void
secretanswer(GtkDialog *dialog, int response, struct secret *s)
{
	const char *pass;

	pass = gtk_entry_get_text(GTK_ENTRY(s->password));
	answers[(response == GTK_RESPONSE_OK) * (1 + (s->user != NULL))](s,
	    pass);
	secrets = g_slist_remove(secrets, dialog);
	gtk_widget_destroy(GTK_WIDGET(dialog));
	g_free(s);
}

static void
ask(GDBusMethodInvocation *invocation, GVariant *args, int kind)
{
	struct secret *s;
	GtkWidget *dialog, *box, *grid, *label, *field, *show;
	const char *network, *user;
	char *ssid, *text;
	int r;

	r = 0;
	user = NULL;
	g_variant_get_child(args, 0, "&o", &network);
	if (g_variant_n_children(args) > 1)
		g_variant_get_child(args, 1, "&s", &user);
	ssid = propstr(network, NETWORK, "Name");
	s = g_new0(struct secret, 1);
	s->invocation = invocation;
	s->min = kinds[kind].min;
	s->max = kinds[kind].max;

	dialog = gtk_dialog_new_with_buttons(
	    "Wi-Fi Network Authentication Required", NULL, 0, "_Cancel",
	    GTK_RESPONSE_CANCEL, NULL);
	s->connect = gtk_dialog_add_button(GTK_DIALOG(dialog), "C_onnect",
	    GTK_RESPONSE_OK);
	gtk_dialog_set_default_response(GTK_DIALOG(dialog), GTK_RESPONSE_OK);
	gtk_window_set_icon_name(GTK_WINDOW(dialog), "network-wireless");
	gtk_window_set_position(GTK_WINDOW(dialog), GTK_WIN_POS_CENTER);
	gtk_window_set_keep_above(GTK_WINDOW(dialog), TRUE);
	gtk_window_set_resizable(GTK_WINDOW(dialog), FALSE);

	box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
	gtk_container_set_border_width(GTK_CONTAINER(box), 12);
	gtk_box_pack_start(GTK_BOX(box), gtk_image_new_from_icon_name(
	    "network-wireless", GTK_ICON_SIZE_DIALOG), FALSE, FALSE, 0);
	grid = gtk_grid_new();
	gtk_grid_set_row_spacing(GTK_GRID(grid), 8);
	gtk_grid_set_column_spacing(GTK_GRID(grid), 12);
	gtk_box_pack_start(GTK_BOX(box), grid, TRUE, TRUE, 0);
	gtk_container_add(GTK_CONTAINER(gtk_dialog_get_content_area(
	    GTK_DIALOG(dialog))), box);

	label = gtk_label_new(NULL);
	text = g_markup_printf_escaped("<b>Authentication required by Wi-Fi "
	    "network</b>\n\n%s the Wi-Fi network “%s”.",
	    kinds[kind].text, ssid != NULL ? ssid : "?");
	gtk_label_set_markup(GTK_LABEL(label), text);
	gtk_label_set_line_wrap(GTK_LABEL(label), TRUE);
	gtk_label_set_max_width_chars(GTK_LABEL(label), 48);
	gtk_label_set_xalign(GTK_LABEL(label), 0);
	gtk_grid_attach(GTK_GRID(grid), label, 0, r++, 2, 1);

	s->user = kinds[kind].user ? gtk_entry_new() : NULL;
	field = s->user != NULL ? s->user : gtk_label_new(user);
	label = gtk_label_new_with_mnemonic("_Username:");
	gtk_label_set_xalign(GTK_LABEL(label), 1);
	gtk_label_set_mnemonic_widget(GTK_LABEL(label), s->user);
	gtk_widget_set_no_show_all(label, s->user == NULL && user == NULL);
	gtk_widget_set_no_show_all(field, s->user == NULL && user == NULL);
	gtk_grid_attach(GTK_GRID(grid), label, 0, r, 1, 1);
	gtk_grid_attach(GTK_GRID(grid), field, 1, r++, 1, 1);
	if (s->user != NULL)
		g_signal_connect(s->user, "changed", G_CALLBACK(secretcheck),
		    s);

	label = gtk_label_new_with_mnemonic(kinds[kind].label);
	gtk_label_set_xalign(GTK_LABEL(label), 1);
	s->password = gtk_entry_new();
	gtk_entry_set_visibility(GTK_ENTRY(s->password), FALSE);
	gtk_entry_set_input_purpose(GTK_ENTRY(s->password),
	    GTK_INPUT_PURPOSE_PASSWORD);
	gtk_entry_set_activates_default(GTK_ENTRY(s->password), TRUE);
	gtk_widget_set_hexpand(s->password, TRUE);
	gtk_label_set_mnemonic_widget(GTK_LABEL(label), s->password);
	g_signal_connect(s->password, "changed", G_CALLBACK(secretcheck), s);
	gtk_grid_attach(GTK_GRID(grid), label, 0, r, 1, 1);
	gtk_grid_attach(GTK_GRID(grid), s->password, 1, r++, 1, 1);

	show = gtk_check_button_new_with_mnemonic("_Show password");
	g_signal_connect(show, "toggled", G_CALLBACK(secretshow), s);
	gtk_grid_attach(GTK_GRID(grid), show, 1, r++, 1, 1);

	g_signal_connect(dialog, "response", G_CALLBACK(secretanswer), s);
	secretcheck(NULL, s);
	secrets = g_slist_prepend(secrets, dialog);
	gtk_widget_show_all(dialog);
	gtk_window_present(GTK_WINDOW(dialog));
	gtk_widget_grab_focus(s->user != NULL ? s->user : s->password);
	g_free(ssid);
	g_free(text);
}

static void
cancel(GDBusMethodInvocation *invocation, GVariant *args, int kind)
{
	(void)args;
	(void)kind;
	while (secrets != NULL)
		gtk_dialog_response(GTK_DIALOG(secrets->data),
		    GTK_RESPONSE_CANCEL);
	g_dbus_method_invocation_return_value(invocation, NULL);
}

static void
release(GDBusMethodInvocation *invocation, GVariant *args, int kind)
{
	(void)args;
	(void)kind;
	g_dbus_method_invocation_return_value(invocation, NULL);
}

static void
agentcall(GDBusConnection *c, const char *sender, const char *path,
    const char *iface, const char *method, GVariant *args,
    GDBusMethodInvocation *invocation, gpointer data)
{
	size_t i;

	(void)c;
	(void)path;
	(void)iface;
	(void)data;
	if (g_strcmp0(sender, owner()) != 0) {
		g_dbus_method_invocation_return_dbus_error(invocation,
		    CANCELED, "Only iwd may ask for secrets");
		return;
	}
	for (i = 0; i < LEN(methods) - 1; i++)
		if (strcmp(method, methods[i].name) == 0)
			break;
	methods[i].handle(invocation, args, methods[i].kind);
}

static void
registeragent(void)
{
	const char *name;

	if ((name = owner()) == NULL || g_strcmp0(name, agentowner) == 0)
		return;
	g_free(agentowner);
	agentowner = g_strdup(name);
	g_dbus_connection_call(bus, IWD, IWD_PATH, IWD ".AgentManager",
	    "RegisterAgent", g_variant_new("(o)", AGENT_PATH), NULL,
	    G_DBUS_CALL_FLAGS_NONE, -1, NULL, NULL, NULL);
}

static void
wifistatus(char **icon, char **tip)
{
	struct network *net;
	GList *stations, *l, *nets;
	char *state;

	stations = paths(STATION);
	for (l = stations; l != NULL && *icon == NULL; l = l->next) {
		state = propstr(l->data, STATION, "State");
		nets = NULL;
		if (g_strcmp0(state, "connected") == 0)
			nets = networks(l->data);
		if (nets != NULL) {
			net = nets->data;
			*icon = sigicon(net->signal, 0);
			*tip = g_strdup_printf("Connected to %s (%d%%)",
			    net->name, percent(net->signal));
		}
		if (*icon == NULL && (g_strcmp0(state, "connecting") == 0 ||
		    g_strcmp0(state, "roaming") == 0)) {
			*icon = g_strdup("network-wireless-acquiring");
			*tip = g_strdup("Connecting…");
		}
		g_list_free_full(nets, netfree);
		g_free(state);
	}
	g_list_free_full(stations, g_free);
}

static void
wiredstatus(char **icon, char **tip)
{
	GList *ifaces, *l;
	char *ip;

	ifaces = wired();
	for (l = ifaces; l != NULL && *icon == NULL; l = l->next) {
		if ((ip = wiredip(l->data)) == NULL)
			continue;
		*icon = g_strdup("network-wired");
		*tip = g_strdup_printf("Wired network (%s)", ip);
		g_free(ip);
	}
	g_list_free_full(ifaces, g_free);
}

static void
update(void)
{
	char *icon, *tip;

	icon = NULL;
	tip = NULL;
	wifistatus(&icon, &tip);
	if (icon == NULL)
		wiredstatus(&icon, &tip);
	gtk_status_icon_set_from_icon_name(tray,
	    icon != NULL ? icon : "nm-no-connection");
	gtk_status_icon_set_tooltip_text(tray, tip != NULL ? tip :
	    owner() != NULL ? "Not connected" :
	    "Wi-Fi service (iwd) is not running");
	g_free(icon);
	g_free(tip);
}

static GtkWidget *
menuitem(const char *icon, const char *text, int bold)
{
	GtkWidget *item, *box, *image, *label;
	char *markup;

	item = gtk_menu_item_new();
	box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
	image = gtk_image_new_from_icon_name(icon, GTK_ICON_SIZE_MENU);
	gtk_widget_set_size_request(image, 16, 16);
	label = gtk_label_new(NULL);
	markup = g_markup_printf_escaped(bold ? "<b>%s</b>" : "%s", text);
	gtk_label_set_markup(GTK_LABEL(label), markup);
	gtk_label_set_xalign(GTK_LABEL(label), 0);
	gtk_box_pack_start(GTK_BOX(box), image, FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(box), label, TRUE, TRUE, 0);
	gtk_container_add(GTK_CONTAINER(item), box);
	g_free(markup);
	return item;
}

static void
append(GtkWidget *parent, GtkWidget *item)
{
	gtk_menu_shell_append(GTK_MENU_SHELL(parent), item);
}

static void
header(GtkWidget *parent, const char *text)
{
	GtkWidget *item;

	item = gtk_menu_item_new_with_label(text);
	gtk_widget_set_sensitive(item, FALSE);
	append(parent, item);
}

static GtkWidget *
action(GtkWidget *parent, const char *label, GCallback cb, const char *path,
    int sensitive)
{
	GtkWidget *item;

	item = gtk_menu_item_new_with_mnemonic(label);
	g_signal_connect_data(item, "activate", cb, g_strdup(path), freepath,
	    0);
	gtk_widget_set_sensitive(item, sensitive);
	append(parent, item);
	return item;
}

static void
connectnet(GtkMenuItem *item, const char *path)
{
	char *name, *title;

	(void)item;
	name = propstr(path, NETWORK, "Name");
	title = g_strdup_printf("Could not connect to “%s”",
	    name != NULL ? name : "?");
	call(path, NETWORK, "Connect", NULL, title);
	g_free(title);
	g_free(name);
}

static void
disconnectst(GtkMenuItem *item, const char *station)
{
	(void)item;
	call(station, STATION, "Disconnect", NULL, "Could not disconnect");
}

static void
forget(GtkMenuItem *item, const char *known)
{
	(void)item;
	call(known, KNOWN, "Forget", NULL, "Could not forget the network");
}

static void
power(GtkCheckMenuItem *item, gpointer data)
{
	GList *list, *l;
	gboolean on;
	size_t i;

	(void)data;
	on = gtk_check_menu_item_get_active(item);
	if (on && hardblocked()) {
		message(GTK_MESSAGE_INFO, "Wi-Fi is switched off",
		    "Turn on the wireless switch of the computer (often on "
		    "its side or front edge, or an Fn key combination).");
		return;
	}
	for (i = 0; i < LEN(powered); i++) {
		list = paths(powered[i]);
		for (l = list; l != NULL; l = l->next)
			g_dbus_connection_call(bus, IWD, l->data,
			    "org.freedesktop.DBus.Properties", "Set",
			    g_variant_new("(ssv)", powered[i], "Powered",
			    g_variant_new_boolean(on)), NULL,
			    G_DBUS_CALL_FLAGS_NONE, -1, NULL, NULL, NULL);
		g_list_free_full(list, g_free);
	}
}

static void
hiddenanswer(GtkDialog *dialog, int response, GtkWidget *entry)
{
	const char *ssid, *station;
	char *title;

	ssid = gtk_entry_get_text(GTK_ENTRY(entry));
	station = g_object_get_data(G_OBJECT(dialog), "station");
	title = g_strdup_printf("Could not connect to “%s”", ssid);
	if (response == GTK_RESPONSE_OK)
		call(station, STATION, "ConnectHiddenNetwork",
		    g_variant_new("(s)", ssid), title);
	g_free(title);
	gtk_widget_destroy(GTK_WIDGET(dialog));
}

static void
hidden(GtkMenuItem *item, const char *station)
{
	GtkWidget *dialog, *grid, *label, *entry;

	(void)item;
	dialog = gtk_dialog_new_with_buttons(
	    "Connect to Hidden Wi-Fi Network", NULL, 0, "_Cancel",
	    GTK_RESPONSE_CANCEL, "C_onnect", GTK_RESPONSE_OK, NULL);
	g_object_set_data_full(G_OBJECT(dialog), "station", g_strdup(station),
	    g_free);
	gtk_dialog_set_default_response(GTK_DIALOG(dialog), GTK_RESPONSE_OK);
	gtk_window_set_icon_name(GTK_WINDOW(dialog), "network-wireless");
	gtk_window_set_position(GTK_WINDOW(dialog), GTK_WIN_POS_CENTER);
	gtk_window_set_keep_above(GTK_WINDOW(dialog), TRUE);
	grid = gtk_grid_new();
	gtk_container_set_border_width(GTK_CONTAINER(grid), 12);
	gtk_grid_set_row_spacing(GTK_GRID(grid), 8);
	gtk_grid_set_column_spacing(GTK_GRID(grid), 12);
	label = gtk_label_new("Enter the name of the hidden Wi-Fi network. "
	    "If it needs a\npassword, you will be asked for it next.");
	gtk_label_set_xalign(GTK_LABEL(label), 0);
	gtk_grid_attach(GTK_GRID(grid), label, 0, 0, 2, 1);
	label = gtk_label_new_with_mnemonic("_Network name:");
	entry = gtk_entry_new();
	gtk_entry_set_max_length(GTK_ENTRY(entry), 32);
	gtk_entry_set_activates_default(GTK_ENTRY(entry), TRUE);
	gtk_widget_set_hexpand(entry, TRUE);
	gtk_label_set_mnemonic_widget(GTK_LABEL(label), entry);
	gtk_grid_attach(GTK_GRID(grid), label, 0, 1, 1, 1);
	gtk_grid_attach(GTK_GRID(grid), entry, 1, 1, 1, 1);
	gtk_container_add(GTK_CONTAINER(gtk_dialog_get_content_area(
	    GTK_DIALOG(dialog))), grid);
	g_signal_connect(dialog, "response", G_CALLBACK(hiddenanswer), entry);
	gtk_widget_show_all(dialog);
	gtk_window_present(GTK_WINDOW(dialog));
}

static void
row(GtkWidget *grid, int *r, const char *name, const char *value)
{
	GtkWidget *l, *v;

	l = gtk_label_new(name);
	v = gtk_label_new(value != NULL ? value : "—");
	gtk_label_set_xalign(GTK_LABEL(l), 1);
	gtk_label_set_xalign(GTK_LABEL(v), 0);
	gtk_label_set_selectable(GTK_LABEL(v), TRUE);
	gtk_style_context_add_class(gtk_widget_get_style_context(l),
	    "dim-label");
	gtk_grid_attach(GTK_GRID(grid), l, 0, *r, 1, 1);
	gtk_grid_attach(GTK_GRID(grid), v, 1, (*r)++, 1, 1);
}

static void
heading(GtkWidget *grid, int *r, const char *text)
{
	GtkWidget *l;
	char *markup;

	l = gtk_label_new(NULL);
	markup = g_markup_printf_escaped("<b>%s</b>", text);
	gtk_label_set_markup(GTK_LABEL(l), markup);
	gtk_label_set_xalign(GTK_LABEL(l), 0);
	gtk_widget_set_margin_top(l, *r > 0 ? 12 : 0);
	gtk_grid_attach(GTK_GRID(grid), l, 0, (*r)++, 2, 1);
	g_free(markup);
}

static void
addresses(GtkWidget *grid, int *r, const char *ifname)
{
	char *value;
	size_t i;

	for (i = 0; i < LEN(addrrows); i++) {
		value = addrrows[i].get(ifname);
		row(grid, r, addrrows[i].label, value);
		g_free(value);
	}
}

static void
wifiinfo(GtkWidget *grid, int *r, const char *station)
{
	struct network *net;
	GVariant *reply, *dict, *v;
	GList *nets;
	const char *mode;
	char *ifname, *text;
	size_t i;

	nets = networks(station);
	net = nets != NULL ? nets->data : NULL;
	if (net == NULL || !net->connected) {
		g_list_free_full(nets, netfree);
		return;
	}
	text = g_strdup_printf("Wi-Fi: %s", net->name);
	heading(grid, r, text);
	g_free(text);
	text = g_strdup_printf("%d%% (%d dBm)", percent(net->signal),
	    net->signal);
	row(grid, r, "Signal", text);
	g_free(text);
	reply = g_dbus_connection_call_sync(bus, IWD, station, DIAGNOSTIC,
	    "GetDiagnostics", NULL, G_VARIANT_TYPE("(a{sv})"),
	    G_DBUS_CALL_FLAGS_NONE, 2000, NULL, NULL);
	dict = reply != NULL ? g_variant_get_child_value(reply, 0) :
	    g_variant_ref_sink(g_variant_new("a{sv}", NULL));
	if (!g_variant_lookup(dict, "Security", "&s", &mode))
		row(grid, r, "Security", security(net->type));
	for (i = 0; i < LEN(diagrows); i++) {
		v = g_variant_lookup_value(dict, diagrows[i].key, NULL);
		if (v == NULL)
			continue;
		text = diagrows[i].format == NULL ?
		    g_variant_dup_string(v, NULL) :
		    g_strdup_printf(diagrows[i].format,
		    g_variant_get_uint32(v) / diagrows[i].divisor);
		row(grid, r, diagrows[i].label, text);
		g_free(text);
		g_variant_unref(v);
	}
	g_variant_unref(dict);
	g_clear_pointer(&reply, g_variant_unref);
	ifname = propstr(station, DEVICE, "Name");
	addresses(grid, r, ifname);
	g_free(ifname);
	g_list_free_full(nets, netfree);
}

static void
info(GtkMenuItem *item, gpointer data)
{
	GtkWidget *dialog, *grid;
	GList *stations, *ifaces, *l;
	char *ip, *speed, *text;
	int r;

	(void)item;
	(void)data;
	r = 0;
	dialog = gtk_dialog_new_with_buttons("Connection Information", NULL,
	    0, "_Close", GTK_RESPONSE_CLOSE, NULL);
	gtk_window_set_icon_name(GTK_WINDOW(dialog), "network-wireless");
	gtk_window_set_position(GTK_WINDOW(dialog), GTK_WIN_POS_CENTER);
	grid = gtk_grid_new();
	gtk_container_set_border_width(GTK_CONTAINER(grid), 12);
	gtk_grid_set_row_spacing(GTK_GRID(grid), 4);
	gtk_grid_set_column_spacing(GTK_GRID(grid), 16);

	stations = paths(STATION);
	for (l = stations; l != NULL; l = l->next)
		wifiinfo(grid, &r, l->data);
	g_list_free_full(stations, g_free);

	ifaces = wired();
	for (l = ifaces; l != NULL; l = l->next) {
		if ((ip = wiredip(l->data)) == NULL)
			continue;
		text = g_strdup_printf("Wired: %s", (char *)l->data);
		heading(grid, &r, text);
		g_free(text);
		speed = readsys("/sys/class/net/%s/speed", l->data);
		text = speed != NULL && atoi(speed) > 0 ?
		    g_strdup_printf("%s Mbit/s", speed) : NULL;
		row(grid, &r, "Speed", text);
		addresses(grid, &r, l->data);
		g_free(text);
		g_free(speed);
		g_free(ip);
	}
	g_list_free_full(ifaces, g_free);

	if (r == 0)
		heading(grid, &r, "Not connected to any network.");
	gtk_container_add(GTK_CONTAINER(gtk_dialog_get_content_area(
	    GTK_DIALOG(dialog))), grid);
	g_signal_connect(dialog, "response", G_CALLBACK(gtk_widget_destroy),
	    NULL);
	gtk_widget_show_all(dialog);
	gtk_window_present(GTK_WINDOW(dialog));
}

static void
diagnosticsanswer(GtkDialog *dialog, int response, GtkTextBuffer *buffer)
{
	GtkTextIter start, end;
	GError *error;
	char *path, *text;
	int ok;

	if (response != RESPONSE_SAVE) {
		gtk_widget_destroy(GTK_WIDGET(dialog));
		return;
	}
	error = NULL;
	path = g_build_filename(g_get_home_dir(), REPORT, NULL);
	gtk_text_buffer_get_bounds(buffer, &start, &end);
	text = gtk_text_buffer_get_text(buffer, &start, &end, FALSE);
	ok = g_file_set_contents(path, text, -1, &error) != 0;
	message(saved[ok].type, saved[ok].title, ok ? path : error->message);
	g_clear_error(&error);
	g_free(text);
	g_free(path);
}

static void
diagnostics(GtkMenuItem *item, gpointer data)
{
	GtkWidget *dialog, *scroll, *view;
	GtkTextBuffer *buffer;
	GError *error;
	char *argv[] = { "jadeos-netinfo", NULL };
	char *out, *err;

	(void)item;
	(void)data;
	error = NULL;
	out = NULL;
	err = NULL;
	if (!g_spawn_sync(NULL, argv, NULL, G_SPAWN_SEARCH_PATH, NULL, NULL,
	    &out, &err, NULL, &error)) {
		message(GTK_MESSAGE_ERROR, "Could not run jadeos-netinfo",
		    error->message);
		g_error_free(error);
		return;
	}
	dialog = gtk_dialog_new_with_buttons("Network Diagnostics", NULL, 0,
	    "_Save to File", RESPONSE_SAVE, "_Close", GTK_RESPONSE_CLOSE,
	    NULL);
	gtk_window_set_icon_name(GTK_WINDOW(dialog), "network-wireless");
	gtk_window_set_default_size(GTK_WINDOW(dialog), 760, 560);
	gtk_window_set_position(GTK_WINDOW(dialog), GTK_WIN_POS_CENTER);
	scroll = gtk_scrolled_window_new(NULL, NULL);
	gtk_widget_set_vexpand(scroll, TRUE);
	view = gtk_text_view_new();
	gtk_text_view_set_editable(GTK_TEXT_VIEW(view), FALSE);
	gtk_text_view_set_monospace(GTK_TEXT_VIEW(view), TRUE);
	gtk_text_view_set_left_margin(GTK_TEXT_VIEW(view), 8);
	buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(view));
	gtk_text_buffer_set_text(buffer, out, -1);
	gtk_text_buffer_insert_at_cursor(buffer, *err != '\0' ?
	    "\n== errors\n" : "", -1);
	gtk_text_buffer_insert_at_cursor(buffer, err, -1);
	gtk_container_add(GTK_CONTAINER(scroll), view);
	gtk_container_add(GTK_CONTAINER(gtk_dialog_get_content_area(
	    GTK_DIALOG(dialog))), scroll);
	g_signal_connect(dialog, "response", G_CALLBACK(diagnosticsanswer),
	    buffer);
	gtk_widget_show_all(dialog);
	gtk_window_present(GTK_WINDOW(dialog));
	g_free(out);
	g_free(err);
}

static void
addnetwork(GtkWidget *parent, struct network *n, const char *station)
{
	GtkWidget *item;
	char *icon, *tip;
	int secure;

	secure = g_strcmp0(n->type, "open") != 0;
	icon = sigicon(n->signal, secure);
	tip = g_strdup_printf("%d%% signal, %s%s", percent(n->signal),
	    secure ? "secured" : "open", n->known ? ", known" : "");
	item = menuitem(icon, n->name, n->connected);
	gtk_widget_set_tooltip_text(item, tip);
	g_signal_connect_data(item, "activate", n->connected ?
	    G_CALLBACK(gtk_true) : G_CALLBACK(connectnet), g_strdup(n->path),
	    freepath, 0);
	append(parent, item);
	item = menuitem(NULL, "Disconnect", 0);
	g_signal_connect_data(item, "activate", G_CALLBACK(disconnectst),
	    g_strdup(station), freepath, 0);
	gtk_widget_set_no_show_all(item, !n->connected);
	append(parent, item);
	g_free(icon);
	g_free(tip);
}

static void
stationsection(const char *station)
{
	GtkWidget *parent;
	GList *nets, *l;
	char *adapter, *model, *ifname, *title;
	int i;

	ifname = propstr(station, DEVICE, "Name");
	adapter = propstr(station, DEVICE, "Adapter");
	model = propstr(adapter, ADAPTER, "Model");
	title = g_strdup_printf("Wi-Fi Networks (%s)",
	    model != NULL && *model != '\0' ? model : ifname);
	header(menu, title);
	g_free(title);
	g_free(model);
	g_free(adapter);
	g_free(ifname);
	if (!propflag(station, DEVICE, "Powered")) {
		header(menu, "Wi-Fi is disabled");
		return;
	}
	nets = networks(station);
	parent = menu;
	for (l = nets, i = 0; l != NULL; l = l->next, i++) {
		if (i == MENU_MAX) {
			parent = gtk_menu_new();
			gtk_menu_item_set_submenu(GTK_MENU_ITEM(action(menu,
			    "More networks", G_CALLBACK(gtk_true), NULL,
			    TRUE)), parent);
		}
		addnetwork(parent, l->data, station);
	}
	if (nets == NULL)
		header(menu, propflag(station, STATION, "Scanning") ?
		    "Searching for networks…" : "No networks found");
	g_list_free_full(nets, netfree);
}

static int
wiredsection(void)
{
	GtkWidget *item;
	GList *ifaces, *l;
	char *ip, *text;
	int connected;

	connected = 0;
	ifaces = wired();
	for (l = ifaces; l != NULL; l = l->next) {
		text = g_strdup_printf("Ethernet Network (%s)",
		    (char *)l->data);
		header(menu, text);
		g_free(text);
		ip = wiredip(l->data);
		connected |= ip != NULL;
		text = ip != NULL ? g_strdup_printf("connected, %s", ip) :
		    g_strdup("cable unplugged or no address");
		item = menuitem("network-wired", text, ip != NULL);
		gtk_widget_set_sensitive(item, FALSE);
		append(menu, item);
		g_free(text);
		g_free(ip);
	}
	if (ifaces != NULL)
		append(menu, gtk_separator_menu_item_new());
	g_list_free_full(ifaces, g_free);
	return connected;
}

static int
wifisection(GList *stations, GList *adapters, int *on)
{
	GList *l;
	char *status;
	int connected, state[WIFI_STATES];
	size_t i;

	connected = 0;
	state[WIFI_NOIWD] = owner() == NULL;
	state[WIFI_NOADAPTER] = adapters == NULL && stations == NULL;
	state[WIFI_DISABLED] = stations == NULL;
	for (i = 0; i < LEN(state) && !state[i]; i++)
		continue;
	if (i < LEN(state))
		header(menu, wifinotes[i]);
	if (hardblocked())
		header(menu, "Wi-Fi is off: turn on the wireless switch");
	for (l = stations; l != NULL; l = l->next) {
		*on |= propflag(l->data, DEVICE, "Powered");
		status = propstr(l->data, STATION, "State");
		connected |= g_strcmp0(status, "connected") == 0;
		stationsection(l->data);
		g_free(status);
	}
	return connected;
}

static void
knownsection(void)
{
	GtkWidget *sub;
	GList *known, *l;
	char *name;

	known = paths(KNOWN);
	sub = gtk_menu_new();
	for (l = known; l != NULL; l = l->next) {
		name = propstr(l->data, KNOWN, "Name");
		action(sub, name != NULL ? name : "?", G_CALLBACK(forget),
		    l->data, TRUE);
		g_free(name);
	}
	gtk_menu_item_set_submenu(GTK_MENU_ITEM(action(menu,
	    "_Forget Network", G_CALLBACK(gtk_true), NULL, known != NULL)),
	    sub);
	g_list_free_full(known, g_free);
}

static void
build(void)
{
	GtkWidget *item;
	GList *children, *l, *stations, *adapters;
	int connected, on;

	children = gtk_container_get_children(GTK_CONTAINER(menu));
	for (l = children; l != NULL; l = l->next)
		gtk_widget_destroy(l->data);
	g_list_free(children);

	on = 0;
	stations = paths(STATION);
	adapters = paths(ADAPTER);
	connected = wiredsection();
	connected |= wifisection(stations, adapters, &on);
	append(menu, gtk_separator_menu_item_new());
	action(menu, "Connect to _Hidden Wi-Fi Network…",
	    G_CALLBACK(hidden), stations != NULL ? stations->data : NULL,
	    on);
	append(menu, gtk_separator_menu_item_new());
	item = gtk_check_menu_item_new_with_mnemonic("Enable _Wi-Fi");
	gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(item),
	    on && !hardblocked());
	gtk_widget_set_sensitive(item, adapters != NULL);
	g_signal_connect(item, "toggled", G_CALLBACK(power), NULL);
	append(menu, item);
	append(menu, gtk_separator_menu_item_new());
	action(menu, "Connection _Information", G_CALLBACK(info), NULL,
	    connected);
	action(menu, "_Diagnostics…", G_CALLBACK(diagnostics), NULL,
	    TRUE);
	knownsection();
	g_list_free_full(stations, g_free);
	g_list_free_full(adapters, g_free);
	gtk_widget_show_all(menu);
}

static void
scan(void)
{
	GList *stations, *l;

	stations = paths(STATION);
	for (l = stations; l != NULL; l = l->next)
		g_dbus_connection_call(bus, IWD, l->data, STATION, "Scan",
		    NULL, NULL, G_DBUS_CALL_FLAGS_NONE, -1, NULL, NULL, NULL);
	g_list_free_full(stations, g_free);
}

static void
popup(guint button, guint32 time)
{
	gtk_status_icon_set_has_tooltip(tray, FALSE);
	build();
	scan();
	placements[time == 0](button, time);
}

static void
popupicon(guint button, guint32 time)
{
	gtk_menu_popup(GTK_MENU(menu), NULL, NULL,
	    gtk_status_icon_position_menu, tray, button, time);
}

static void
popuppointer(guint button, guint32 time)
{
	(void)button;
	(void)time;
	gtk_menu_popup_at_pointer(GTK_MENU(menu), NULL);
}

static void
closed(gpointer data)
{
	(void)data;
	gtk_status_icon_set_has_tooltip(tray, TRUE);
}

static void
clicked(gpointer data)
{
	(void)data;
	popup(1, gtk_get_current_event_time());
}

static void
rightclicked(GtkStatusIcon *icon, guint button, guint time, gpointer data)
{
	(void)icon;
	(void)data;
	popup(button, time);
}

static gboolean
refresh(gpointer data)
{
	(void)data;
	pending = 0;
	update();
	if (gtk_widget_get_visible(menu))
		build();
	return G_SOURCE_REMOVE;
}

static void
changed(gpointer data)
{
	(void)data;
	if (pending == 0)
		pending = g_timeout_add(300, refresh, NULL);
}

static void
ownerchanged(gpointer data)
{
	registeragent();
	changed(data);
}

static gboolean
tick(gpointer data)
{
	(void)data;
	update();
	return G_SOURCE_CONTINUE;
}

static void
startup(GApplication *app, gpointer data)
{
	static const GDBusInterfaceVTable vtable = { agentcall, NULL, NULL,
	    { 0 } };
	GDBusNodeInfo *node;
	GError *error;
	size_t i;

	(void)data;
	error = NULL;
	if ((bus = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error)) == NULL)
		errx(1, "system bus: %s", error->message);
	node = g_dbus_node_info_new_for_xml(agentxml, NULL);
	if (!g_dbus_connection_register_object(bus, AGENT_PATH,
	    node->interfaces[0], &vtable, NULL, NULL, &error))
		errx(1, "agent: %s", error->message);
	manager = g_dbus_object_manager_client_new_sync(bus,
	    G_DBUS_OBJECT_MANAGER_CLIENT_FLAGS_DO_NOT_AUTO_START, IWD, "/",
	    NULL, NULL, NULL, NULL, &error);
	if (manager == NULL)
		errx(1, "iwd: %s", error->message);
	for (i = 0; i < LEN(events); i++)
		g_signal_connect_swapped(manager, events[i],
		    G_CALLBACK(changed), NULL);
	g_signal_connect_swapped(manager, "notify::name-owner",
	    G_CALLBACK(ownerchanged), NULL);
	registeragent();

	menu = gtk_menu_new();
	g_signal_connect_swapped(menu, "deactivate", G_CALLBACK(closed),
	    NULL);
	tray = gtk_status_icon_new();
	gtk_status_icon_set_title(tray, "Network");
	g_signal_connect_swapped(tray, "activate", G_CALLBACK(clicked), NULL);
	g_signal_connect(tray, "popup-menu", G_CALLBACK(rightclicked), NULL);
	update();
	g_timeout_add_seconds(10, tick, NULL);
	g_application_hold(app);
}

static void
activate(GApplication *app, gpointer data)
{
	(void)app;
	(void)data;
	if (started || openmenu)
		popup(0, 0);
	started = 1;
	openmenu = 0;
}

static int
commandline(GApplication *app, GApplicationCommandLine *cmdline,
    gpointer data)
{
	char **argv;
	int argc;

	(void)data;
	argv = g_application_command_line_get_arguments(cmdline, &argc);
	openmenu = argc == 2 && strcmp(argv[1], "--menu") == 0;
	g_strfreev(argv);
	if (argc > 1 && !openmenu) {
		g_application_command_line_printerr(cmdline,
		    "usage: jadeos-wifi [--menu]\n");
		return 1;
	}
	g_application_activate(app);
	return 0;
}

static void
freepath(gpointer data, GClosure *closure)
{
	(void)closure;
	g_free(data);
}

int
main(int argc, char *argv[])
{
	GtkApplication *app;
	int status;

	app = gtk_application_new("org.jadeos.Wifi",
	    G_APPLICATION_HANDLES_COMMAND_LINE);
	g_signal_connect(app, "startup", G_CALLBACK(startup), NULL);
	g_signal_connect(app, "activate", G_CALLBACK(activate), NULL);
	g_signal_connect(app, "command-line", G_CALLBACK(commandline), NULL);
	status = g_application_run(G_APPLICATION(app), argc, argv);
	g_object_unref(app);
	return status;
}
