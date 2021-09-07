### 
Author: suwonchon(schon@ebay.com)
###

class Dashing.Monitor extends Dashing.Widget
  ready: ->
    #console.log '[INFO] Get Data ready from monitor'

    if not @get('items')
      @set 'status', 'NO DATA'

    if @get('unordered')
      $(@node).find('ol').remove()
    else
      $(@node).find('ul').remove()

  onData: (data) ->
    #console.log '[INFO] Get Data onData from monitor'
    #console.log @get('items').length

    status = switch
      when not (data.hasOwnProperty('items')) then 'NO DATA'
      when @get('items').length < 1 then 'NO DATA'
      else 'success'

    #console.log 'status: '+status
    @set 'status', status
