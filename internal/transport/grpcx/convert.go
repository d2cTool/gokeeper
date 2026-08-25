package grpcx

import (
	"gokeeper/internal/transport/grpc/pb"
	"gokeeper/internal/vault"
)

func itemToPB(it vault.Item) *pb.Item {
	out := &pb.Item{
		Id:        it.ID,
		Type:      string(it.Type),
		Metadata:  it.Metadata,
		Version:   it.Version,
		UpdatedAt: it.UpdatedAt,
		Deleted:   it.Deleted,
	}
	if it.Login != nil {
		out.Login = &pb.LoginPayload{Url: it.Login.URL, Username: it.Login.Username, Password: it.Login.Password}
	}
	if it.Text != nil {
		out.Text = &pb.TextPayload{Title: it.Text.Title, Body: it.Text.Body}
	}
	if it.Binary != nil {
		out.Binary = &pb.BinaryPayload{Filename: it.Binary.Filename, Data: it.Binary.Data}
	}
	if it.Card != nil {
		out.Card = &pb.CardPayload{
			Holder: it.Card.Holder, Number: it.Card.Number,
			ExpMonth: it.Card.ExpMonth, ExpYear: it.Card.ExpYear, Cvv: it.Card.CVV,
		}
	}
	return out
}

func itemFromPB(in *pb.Item) vault.Item {
	if in == nil {
		return vault.Item{}
	}
	return upsertToItem(in.Id, in.Type, in.Metadata, in.Login, in.Text, in.Binary, in.Card, in.Version, in.UpdatedAt, in.Deleted)
}

func upsertToItem(id, typ, meta string, login *pb.LoginPayload, text *pb.TextPayload, binary *pb.BinaryPayload, card *pb.CardPayload, ver, updated int64, deleted bool) vault.Item {
	it := vault.Item{ID: id, Type: vault.Type(typ), Metadata: meta, Version: ver, UpdatedAt: updated, Deleted: deleted}
	if login != nil {
		it.Login = &vault.LoginPayload{URL: login.Url, Username: login.Username, Password: login.Password}
	}
	if text != nil {
		it.Text = &vault.TextPayload{Title: text.Title, Body: text.Body}
	}
	if binary != nil {
		it.Binary = &vault.BinaryPayload{Filename: binary.Filename, Data: binary.Data}
	}
	if card != nil {
		it.Card = &vault.CardPayload{Holder: card.Holder, Number: card.Number, ExpMonth: card.ExpMonth, ExpYear: card.ExpYear, CVV: card.Cvv}
	}
	return it
}
