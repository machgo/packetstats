package output

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/machgo/packetstats/pkg/config"
	"github.com/machgo/packetstats/pkg/flow"
	"github.com/machgo/packetstats/pkg/vpn"
	"github.com/streadway/amqp"
)

func PublishMessages(publish <-chan flow.Flow) {

	url := config.GetInstance().RabbitMq.Url
	routingkey := config.GetInstance().RabbitMq.Routingkey
	exchange := config.GetInstance().RabbitMq.Exchange

	conn, err := amqp.Dial(url)
	failOnError(err, "Failed to connect to RabbitMQ")
	defer conn.Close()

	ch, err := conn.Channel()
	failOnError(err, "Failed to open a channel")
	defer ch.Close()

	for p := range publish {

		vpn.FillSessionName(&p)

		jsonMessage, _ := json.Marshal(p)
		fmt.Println(string(jsonMessage))

		err = ch.Publish(
			exchange,   // exchange
			routingkey, // routing key
			false,      // mandatory
			false,      // immediate
			amqp.Publishing{
				ContentType: "text/json",
				Body:        jsonMessage,
			})
		failOnError(err, "Failed to publish a message")
	}
}

func failOnError(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %s", msg, err)
	}
}
