package grpcx

import (
	"gokeeper/internal/transport/grpc/pb"
	"gokeeper/internal/vault"
)

func itemToPB(it vault.Item) *pb.Item {
	b := pb.Item_builder{
		Id:        it.ID,
		Type:      string(it.Type),
		Metadata:  it.Metadata,
		Version:   it.Version,
		UpdatedAt: it.UpdatedAt,
		Deleted:   it.Deleted,
	}
	if it.Login != nil {
		b.Login = pb.LoginPayload_builder{
			Url: it.Login.URL, Username: it.Login.Username, Password: it.Login.Password,
		}.Build()
	}
	if it.Text != nil {
		b.Text = pb.TextPayload_builder{Title: it.Text.Title, Body: it.Text.Body}.Build()
	}
	if it.Binary != nil {
		b.Binary = pb.BinaryPayload_builder{Filename: it.Binary.Filename, Data: it.Binary.Data}.Build()
	}
	if it.Card != nil {
		b.Card = pb.CardPayload_builder{
			Holder: it.Card.Holder, Number: it.Card.Number,
			ExpMonth: it.Card.ExpMonth, ExpYear: it.Card.ExpYear, Cvv: it.Card.CVV,
		}.Build()
	}
	return b.Build()
}

func itemFromPB(in *pb.Item) vault.Item {
	if in == nil {
		return vault.Item{}
	}
	return upsertToItem(in.GetId(), in.GetType(), in.GetMetadata(), in.GetLogin(), in.GetText(), in.GetBinary(), in.GetCard(), in.GetVersion(), in.GetUpdatedAt(), in.GetDeleted())
}

func upsertToItem(id, typ, meta string, login *pb.LoginPayload, text *pb.TextPayload, binary *pb.BinaryPayload, card *pb.CardPayload, ver, updated int64, deleted bool) vault.Item {
	it := vault.Item{ID: id, Type: vault.Type(typ), Metadata: meta, Version: ver, UpdatedAt: updated, Deleted: deleted}
	if login != nil {
		it.Login = &vault.LoginPayload{URL: login.GetUrl(), Username: login.GetUsername(), Password: login.GetPassword()}
	}
	if text != nil {
		it.Text = &vault.TextPayload{Title: text.GetTitle(), Body: text.GetBody()}
	}
	if binary != nil {
		it.Binary = &vault.BinaryPayload{Filename: binary.GetFilename(), Data: binary.GetData()}
	}
	if card != nil {
		it.Card = &vault.CardPayload{
			Holder: card.GetHolder(), Number: card.GetNumber(),
			ExpMonth: card.GetExpMonth(), ExpYear: card.GetExpYear(), CVV: card.GetCvv(),
		}
	}
	return it
}
