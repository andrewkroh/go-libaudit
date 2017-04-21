package aucoalesce

import (
	"fmt"
	"math"
	"os/user"
	"time"
)

const cacheTimeout = 0

var (
	userLookup  = NewUserCache()
	groupLookup = NewGroupCache()
)

type stringItem struct {
	timeout time.Time
	value   string
}

func (i *stringItem) isExpired() bool {
	return time.Now().After(i.timeout)
}

// UserCache is a cache of UID to username.
type UserCache map[string]stringItem

// NewUserCache returns a new UserCache.
func NewUserCache() UserCache {
	return map[string]stringItem{
		"0": {timeout: time.Unix(math.MaxInt64, 0), value: "root"},
	}
}

// LookupUID looks up a UID and returns the username associated with it. If
// no username could be found an empty string is returned. The value will be
// cached for a minute. This requires cgo on Linux.
func (c UserCache) LookupUID(uid string) string {
	if uid == "" || uid == "unset" {
		return ""
	}

	if item, found := c[uid]; found && !item.isExpired() {
		return item.value
	}

	// Cache the value (even on error).
	user, err := user.LookupId(uid)
	if err != nil {
		fmt.Println("LOOKUP_ERROR", err)
		c[uid] = stringItem{timeout: time.Now().Add(cacheTimeout), value: ""}
		return ""
	}

	c[uid] = stringItem{timeout: time.Now().Add(cacheTimeout), value: user.Username}
	return user.Username
}

// GroupCache is a cache of GID to group name.
type GroupCache map[string]stringItem

// NewGroupCache returns a new GroupCache.
func NewGroupCache() GroupCache {
	return map[string]stringItem{
		"0": {timeout: time.Unix(math.MaxInt64, 0), value: "root"},
	}
}

// LookupGID looks up a GID and returns the group associated with it. If
// no group could be found an empty string is returned. The value will be
// cached for a minute. This requires cgo on Linux.
func (c GroupCache) LookupGID(gid string) string {
	if gid == "" || gid == "unset" {
		return ""
	}

	if item, found := c[gid]; found && !item.isExpired() {
		return item.value
	}

	// Cache the value (even on error).
	group, err := user.LookupGroupId(gid)
	if err != nil {
		fmt.Println("LOOKUP_ERROR", err)
		c[gid] = stringItem{timeout: time.Now().Add(cacheTimeout), value: ""}
		return ""
	}

	c[gid] = stringItem{timeout: time.Now().Add(cacheTimeout), value: group.Name}
	return group.Name
}
