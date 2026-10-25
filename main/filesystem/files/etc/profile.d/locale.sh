# Export the system locale from /etc/locale.conf (and ~/.config/locale.conf)
# unless LANG is already set.
if [ -z "$LANG" ]; then
	for conf in "$HOME/.config/locale.conf" /etc/locale.conf; do
		if [ -r "$conf" ]; then
			. "$conf"
			break
		fi
	done
	unset conf
	export LANG LC_CTYPE LC_NUMERIC LC_TIME LC_COLLATE LC_MONETARY LC_MESSAGES \
		LC_PAPER LC_NAME LC_ADDRESS LC_TELEPHONE LC_MEASUREMENT LC_IDENTIFICATION
	[ -n "$LANG" ] || export LANG=C.UTF-8
fi
