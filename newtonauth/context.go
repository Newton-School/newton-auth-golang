package newtonauth

import "context"

type contextKey string

const userContextKey contextKey = "newton_user"

func UserFromContext(ctx context.Context) (*User, bool) {
	user, ok := ctx.Value(userContextKey).(*User)
	return user, ok && user != nil
}
